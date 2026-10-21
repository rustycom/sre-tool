package isolation

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/events"
)

// Gauge is the part of a Prometheus gauge the service sets.
type Gauge interface{ Set(float64) }

// Service creates, removes and reports isolations. It keeps no state of its
// own: everything it returns is read back from the cluster.
type Service struct {
	client    kubernetes.Interface
	recorder  events.EventRecorder
	podCIDRs  []string
	protected map[string]bool
	active    Gauge

	// mu serialises mutations, so a create and a delete of the same isolation
	// cannot interleave. They are fast, so callers wait.
	mu sync.Mutex
}

// NewService returns a Service. podCIDRs go into every policy's ipBlock
// except list; protected namespaces are refused; active is set to
// the number of isolations in the cluster after every mutation.
func NewService(client kubernetes.Interface, recorder events.EventRecorder, podCIDRs []string, protected map[string]bool, active Gauge) *Service {
	return &Service{client: client, recorder: recorder, podCIDRs: podCIDRs, protected: protected, active: active}
}

// CreateResult lists what Create did, by namespace/name.
type CreateResult struct {
	ID        string   `json:"id"`
	Created   []string `json:"created"`
	Repaired  []string `json:"repaired"`
	Unchanged []string `json:"unchanged"`
	Warnings  []string `json:"warnings,omitempty"`
}

// Create applies a validated request: guards, name check and
// preflight first, then an ownership check of every target name before any
// write, then create or repair each policy. A partial failure keeps what was
// created: partial containment beats none, and a retry completes the set.
func (s *Service) Create(ctx context.Context, req Request) (CreateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := Normalize(req)
	id := ID(n)
	cluster, existing, err := s.snapshot(ctx, slices.Concat(n.Isolate.A.Namespaces, n.Isolate.B.Namespaces))
	if err != nil {
		return CreateResult{}, err
	}
	if err := CheckGuards(n, cluster); err != nil {
		return CreateResult{}, err
	}
	if err := s.checkName(ctx, n, id); err != nil {
		return CreateResult{}, err
	}

	desired := BuildPolicies(n, id, s.podCIDRs)
	byName := map[string]*networkingv1.NetworkPolicy{}
	for i := range existing {
		byName[key(&existing[i])] = &existing[i]
	}
	// Check ownership of every name before writing anything, so a 409 never
	// leaves half an isolation behind. This runs before preflight: a policy
	// squatting on our name is a name_conflict, which force cannot override.
	for i := range desired {
		if cur := byName[key(&desired[i])]; cur != nil && !isOwnPolicy(*cur, id) {
			return CreateResult{}, &Error{Status: http.StatusConflict, Code: "name_conflict",
				Message: fmt.Sprintf("NetworkPolicy %s already exists and is not managed by isolation %s; refusing to overwrite it", key(cur), id),
				Details: map[string]any{"policy": key(cur)}}
		}
	}

	res := CreateResult{ID: id, Created: []string{}, Repaired: []string{}, Unchanged: []string{}}
	conflicts := Preflight(n, id, existing, cluster.Pods)
	// Another isolation's "everything except X" policy on the same pods would
	// re-admit what this one blocks, and ours would re-admit what it blocks:
	// policies are OR'd, so both would stop working. force cannot fix that.
	if other := otherIsolations(conflicts); len(other) > 0 {
		return CreateResult{}, &Error{Status: http.StatusConflict, Code: "isolation_overlap",
			Message: fmt.Sprintf("these pods are already in isolation %s; two isolations on the same pods cancel each other, "+
				"so this cannot be forced; delete the existing isolation first", strings.Join(other, ", ")),
			Details: map[string]any{"policies": conflicts, "isolations": other}}
	}
	forced := len(conflicts) > 0
	if forced && !req.Force {
		return CreateResult{}, conflictError(conflicts)
	}
	for _, c := range conflicts {
		res.Warnings = append(res.Warnings, fmt.Sprintf("forced past conflicting policy %s (side %s); it is still in effect and policies are additive", c.Policy, c.Side))
	}
	// A side that selects no running pod is most likely a typo. Warn rather
	// than refuse: a side may be scaled to zero on purpose, and the policies
	// still apply to matching pods created later.
	for _, sd := range []struct {
		name string
		side Side
	}{{"a", *n.Isolate.A}, {"b", *n.Isolate.B}} {
		if countRunning(sd.side, cluster.Pods) == 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("side %s matches 0 running pods in %s; check the selector: nothing is isolated until a matching pod exists",
				sd.name, strings.Join(sd.side.Namespaces, ",")))
		}
	}

	if forced {
		for i := range desired {
			desired[i].Annotations[AnnotationForced] = "true"
		}
	}

	var failed []string
	for i := range desired {
		d := &desired[i]
		obj, err := s.createOrRepair(ctx, d, byName[key(d)], &res)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", key(d), err))
			continue
		}
		if forced {
			s.recorder.Eventf(obj, nil, corev1.EventTypeWarning, "IsolationForced", "Create",
				"isolation %s was forced past %d conflicting policies", id, len(conflicts))
		}
	}
	s.refreshActive(ctx)
	if len(failed) > 0 {
		return CreateResult{}, &Error{Status: http.StatusInternalServerError, Code: "partial_apply",
			Message: fmt.Sprintf("%d of %d policies failed; the others are in place, and retrying the same request completes the set", len(failed), len(desired)),
			Details: map[string]any{"created": res.Created, "repaired": res.Repaired, "failed": failed}}
	}
	return res, nil
}

// otherIsolations returns the sorted, unique IDs of other isolations among
// the conflicts.
func otherIsolations(conflicts []Conflict) []string {
	var ids []string
	for _, c := range conflicts {
		if c.IsolationID != "" {
			ids = append(ids, c.IsolationID)
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

// countRunning counts the pods of a side that are not finished. The selector
// was validated, so a conversion error cannot happen; it counts as no match.
func countRunning(side Side, pods []corev1.Pod) int {
	sel, err := metav1.LabelSelectorAsSelector(labelSelector(side))
	if err != nil {
		return 0
	}
	n := 0
	for _, p := range pods {
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		if slices.Contains(side.Namespaces, p.Namespace) && sel.Matches(labels.Set(p.Labels)) {
			n++
		}
	}
	return n
}

// createOrRepair writes d when it is missing or differs from cur, and returns
// the policy as it now exists.
func (s *Service) createOrRepair(ctx context.Context, d, cur *networkingv1.NetworkPolicy, res *CreateResult) (*networkingv1.NetworkPolicy, error) {
	api := s.client.NetworkingV1().NetworkPolicies(d.Namespace)
	switch {
	case cur == nil:
		created, err := api.Create(ctx, d, metav1.CreateOptions{})
		if err != nil {
			return nil, fmt.Errorf("create: %w", err)
		}
		res.Created = append(res.Created, key(d))
		s.recorder.Eventf(created, nil, corev1.EventTypeNormal, "IsolationApplied", "Create", "created for isolation %s", d.Labels[LabelIsolationID])
		return created, nil
	case needsRepair(cur, d):
		// Keep labels and annotations others added; overwrite ours. The
		// update carries cur's resourceVersion, so a concurrent edit fails
		// instead of being silently overwritten.
		upd := cur.DeepCopy()
		upd.Spec = d.Spec
		if upd.Labels == nil {
			upd.Labels = map[string]string{}
		}
		if upd.Annotations == nil {
			upd.Annotations = map[string]string{}
		}
		for k, v := range d.Labels {
			upd.Labels[k] = v
		}
		delete(upd.Annotations, AnnotationForced)
		for k, v := range d.Annotations {
			upd.Annotations[k] = v
		}
		updated, err := api.Update(ctx, upd, metav1.UpdateOptions{})
		if err != nil {
			return nil, fmt.Errorf("repair: %w", err)
		}
		res.Repaired = append(res.Repaired, key(d))
		s.recorder.Eventf(updated, nil, corev1.EventTypeNormal, "IsolationApplied", "Repair", "repaired for isolation %s", d.Labels[LabelIsolationID])
		return updated, nil
	default:
		res.Unchanged = append(res.Unchanged, key(d))
		return cur, nil
	}
}

// needsRepair reports whether cur differs from d in anything the tool owns:
// the spec, its labels, or its annotations (including a forced flag that d
// does not carry).
func needsRepair(cur, d *networkingv1.NetworkPolicy) bool {
	if !equality.Semantic.DeepEqual(cur.Spec, d.Spec) {
		return true
	}
	for k, v := range d.Labels {
		if cur.Labels[k] != v {
			return true
		}
	}
	for _, k := range []string{AnnotationRequest, AnnotationExpectedPolicy, AnnotationForced} {
		if cur.Annotations[k] != d.Annotations[k] {
			return true
		}
	}
	return false
}

// snapshot reads what the guards and preflight need from the request's
// namespaces. Protected namespaces are not read: the guards refuse them.
func (s *Service) snapshot(ctx context.Context, namespaces []string) (Cluster, []networkingv1.NetworkPolicy, error) {
	c := Cluster{Protected: s.protected, Namespaces: map[string]bool{}}
	var policies []networkingv1.NetworkPolicy
	slices.Sort(namespaces)
	for _, ns := range slices.Compact(namespaces) {
		if s.protected[ns] {
			continue
		}
		if _, err := s.client.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{}); apierrors.IsNotFound(err) {
			continue
		} else if err != nil {
			return Cluster{}, nil, fmt.Errorf("get namespace %s: %w", ns, err)
		}
		c.Namespaces[ns] = true
		pods, err := s.client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return Cluster{}, nil, fmt.Errorf("list pods in %s: %w", ns, err)
		}
		c.Pods = append(c.Pods, pods.Items...)
		nps, err := s.client.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return Cluster{}, nil, fmt.Errorf("list network policies in %s: %w", ns, err)
		}
		policies = append(policies, nps.Items...)
	}
	return c, policies, nil
}

// checkName returns 409 name_conflict when a named request reuses the name
// of an isolation with a different identity. Generated IDs are a
// hash of the isolate block, so a difference there (allowEmptySelector only)
// is drift that Create repairs.
func (s *Service) checkName(ctx context.Context, n Request, id string) error {
	if n.Name == "" {
		return nil
	}
	policies, err := s.listManaged(ctx, id)
	if err != nil {
		return err
	}
	identity := Identity(n)
	for _, p := range policies {
		if p.Annotations[AnnotationRequest] != identity {
			return &Error{Status: http.StatusConflict, Code: "name_conflict",
				Message: fmt.Sprintf("isolation %s already exists for a different request; delete it or choose another name", id),
				Details: map[string]any{"id": id, "policy": key(&p)}}
		}
	}
	return nil
}

// listManaged lists, in all namespaces, the policies that carry both the
// managed-by label and isolation id. These two labels are the only way the
// tool decides an object is its own. An id that is not a valid
// label value cannot be on any policy, so it matches nothing.
func (s *Service) listManaged(ctx context.Context, id string) ([]networkingv1.NetworkPolicy, error) {
	sel, err := labels.ValidatedSelectorFromSet(labels.Set{LabelManagedBy: ManagedByValue, LabelIsolationID: id})
	if err != nil || id == "" {
		return nil, nil
	}
	list, err := s.client.NetworkingV1().NetworkPolicies(metav1.NamespaceAll).List(ctx, metav1.ListOptions{LabelSelector: sel.String()})
	if err != nil {
		return nil, fmt.Errorf("list policies of isolation %s: %w", id, err)
	}
	return list.Items, nil
}

// RefreshActive sets the active-isolations gauge from a cluster list.
func (s *Service) RefreshActive(ctx context.Context) error {
	list, err := s.client.NetworkingV1().NetworkPolicies(metav1.NamespaceAll).List(ctx,
		metav1.ListOptions{LabelSelector: LabelManagedBy + "=" + ManagedByValue + "," + LabelIsolationID})
	if err != nil {
		return fmt.Errorf("list managed policies: %w", err)
	}
	ids := map[string]bool{}
	for _, p := range list.Items {
		ids[p.Labels[LabelIsolationID]] = true
	}
	s.active.Set(float64(len(ids)))
	return nil
}

// refreshActive is best effort after a mutation: the mutation already
// happened, and a stale gauge must not turn its result into an error.
func (s *Service) refreshActive(ctx context.Context) { _ = s.RefreshActive(ctx) }

func key(p *networkingv1.NetworkPolicy) string { return p.Namespace + "/" + p.Name }

// DeleteResult lists the policies Delete removed, by namespace/name.
type DeleteResult struct {
	ID      string   `json:"id"`
	Deleted []string `json:"deleted"`
	Message string   `json:"message,omitempty"`
}

// Delete removes every policy carrying the managed-by label and this
// isolation ID, found by label in all namespaces, so it needs nothing from
// memory and works after a restart. Each delete carries the
// listed object's UID as a precondition: if the object was replaced between
// list and delete, the API server refuses instead of deleting the new one.
// Deleting an unknown ID succeeds with an empty list.
func (s *Service) Delete(ctx context.Context, id string) (DeleteResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	policies, err := s.listManaged(ctx, id)
	if err != nil {
		return DeleteResult{}, err
	}
	res := DeleteResult{ID: id, Deleted: []string{}}
	// Keep going past a failure: turning isolation off should remove as
	// much as it can, and a retry removes the rest.
	var failed []string
	for i := range policies {
		p := &policies[i]
		uid := p.UID
		err := s.client.NetworkingV1().NetworkPolicies(p.Namespace).Delete(ctx, p.Name,
			metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
		// NotFound and a failed UID precondition (Conflict) both mean the
		// object we listed is gone; anything now at that name is not it.
		if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
			continue
		}
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", key(p), err))
			continue
		}
		res.Deleted = append(res.Deleted, key(p))
		s.recorder.Eventf(p, nil, corev1.EventTypeNormal, "IsolationRemoved", "Delete", "removed for isolation %s", id)
	}
	s.refreshActive(ctx)
	if len(failed) > 0 {
		return DeleteResult{}, &Error{Status: http.StatusInternalServerError, Code: "partial_delete",
			Message: fmt.Sprintf("isolation %s: %d of %d policies could not be deleted (%s) and are still in effect; retry the same DELETE",
				id, len(failed), len(policies), strings.Join(failed, "; ")),
			Details: map[string]any{"id": id, "deleted": res.Deleted, "failed": failed}}
	}
	if len(res.Deleted) == 0 {
		res.Message = fmt.Sprintf("no policies carry isolation ID %s; nothing to delete", id)
	}
	return res, nil
}

// Status is one isolation as read back from the cluster.
type Status struct {
	ID               string         `json:"id"`
	Request          *Request       `json:"request"` // nil when the annotation is unreadable
	Policies         []string       `json:"policies"`
	ExpectedPolicies int            `json:"expectedPolicies"`
	Complete         bool           `json:"complete"`
	Drifted          bool           `json:"drifted"`
	Forced           bool           `json:"forced"`
	MatchedPods      map[string]int `json:"matchedPods"`
	CreatedAt        metav1.Time    `json:"createdAt"`
}

// List returns every isolation in the cluster, sorted by ID.
func (s *Service) List(ctx context.Context) ([]Status, error) {
	list, err := s.client.NetworkingV1().NetworkPolicies(metav1.NamespaceAll).List(ctx,
		metav1.ListOptions{LabelSelector: LabelManagedBy + "=" + ManagedByValue + "," + LabelIsolationID})
	if err != nil {
		return nil, fmt.Errorf("list managed policies: %w", err)
	}
	byID := map[string][]networkingv1.NetworkPolicy{}
	for _, p := range list.Items {
		id := p.Labels[LabelIsolationID]
		byID[id] = append(byID[id], p)
	}
	out := []Status{}
	for _, id := range slices.Sorted(maps.Keys(byID)) {
		st, err := s.status(ctx, id, byID[id])
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, nil
}

// Get returns one isolation, or 404 not_found when no policy carries the ID.
func (s *Service) Get(ctx context.Context, id string) (Status, error) {
	policies, err := s.listManaged(ctx, id)
	if err != nil {
		return Status{}, err
	}
	if len(policies) == 0 {
		return Status{}, &Error{Status: http.StatusNotFound, Code: "not_found",
			Message: fmt.Sprintf("no policies carry isolation ID %s", id), Details: map[string]any{"id": id}}
	}
	return s.status(ctx, id, policies)
}

// status compares the policies found with the ones the stored request would
// generate today. A missing policy makes it incomplete; a changed spec, or an
// unreadable or inconsistent request annotation, makes it drifted.
func (s *Service) status(ctx context.Context, id string, policies []networkingv1.NetworkPolicy) (Status, error) {
	slices.SortFunc(policies, func(x, y networkingv1.NetworkPolicy) int { return strings.Compare(key(&x), key(&y)) })
	first := policies[0]
	st := Status{ID: id, Policies: []string{}, MatchedPods: map[string]int{"a": 0, "b": 0}, CreatedAt: first.CreationTimestamp}
	st.ExpectedPolicies, _ = strconv.Atoi(first.Annotations[AnnotationExpectedPolicy])
	st.Complete = len(policies) == st.ExpectedPolicies

	var req Request
	if err := json.Unmarshal([]byte(first.Annotations[AnnotationRequest]), &req); err == nil && req.Isolate.A != nil && req.Isolate.B != nil {
		st.Request = &req
	}
	desired := map[string]networkingv1.NetworkPolicySpec{}
	if st.Request != nil {
		for _, d := range BuildPolicies(req, id, s.podCIDRs) {
			desired[key(&d)] = d.Spec
		}
	}
	for _, p := range policies {
		st.Policies = append(st.Policies, key(&p))
		st.Forced = st.Forced || p.Annotations[AnnotationForced] == "true"
		if p.CreationTimestamp.Before(&st.CreatedAt) {
			st.CreatedAt = p.CreationTimestamp
		}
		want, ok := desired[key(&p)]
		if !ok || p.Annotations[AnnotationRequest] != first.Annotations[AnnotationRequest] || !equality.Semantic.DeepEqual(p.Spec, want) {
			st.Drifted = true
		}
	}
	if st.Request == nil {
		return st, nil
	}
	for side, sd := range map[string]*Side{"a": req.Isolate.A, "b": req.Isolate.B} {
		sel, err := metav1.LabelSelectorAsSelector(labelSelector(*sd))
		if err != nil {
			st.Drifted = true
			continue
		}
		for _, ns := range sd.Namespaces {
			pods, err := s.client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: sel.String()})
			if err != nil {
				return Status{}, fmt.Errorf("list pods of isolation %s in %s: %w", id, ns, err)
			}
			for _, p := range pods.Items {
				if p.Status.Phase != corev1.PodSucceeded && p.Status.Phase != corev1.PodFailed {
					st.MatchedPods[side]++
				}
			}
		}
	}
	return st, nil
}
