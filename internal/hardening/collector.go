package hardening

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"
)

// Error is a request error with its HTTP status and SPEC §8 code.
type Error struct {
	Status  int
	Code    string
	Message string
	Details map[string]any
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func invalid(format string, args ...any) *Error {
	return &Error{Status: http.StatusBadRequest, Code: "invalid_request", Message: fmt.Sprintf(format, args...)}
}

// Request is the body of plan and apply. PlanHash is required by apply only.
type Request struct {
	Namespaces []string `json:"namespaces"`
	PlanHash   string   `json:"planHash,omitempty"`
}

// Decode parses a JSON or YAML body strictly, as isolation requests are, and
// returns the namespaces sorted and de-duplicated. The service checks the
// --max-namespaces bound and, for apply, the planHash.
func Decode(body []byte) (Request, error) {
	var r Request
	if err := yaml.UnmarshalStrict(body, &r); err != nil {
		return Request{}, invalid("cannot parse the request: %v", err)
	}
	slices.Sort(r.Namespaces)
	r.Namespaces = slices.Compact(r.Namespaces)
	if len(r.Namespaces) == 0 {
		return Request{}, invalid("namespaces must list at least one namespace")
	}
	for _, ns := range r.Namespaces {
		if errs := validation.IsDNS1123Label(ns); len(errs) > 0 {
			return Request{}, invalid("namespace %q is not a valid name: %s", ns, strings.Join(errs, "; "))
		}
	}
	return r, nil
}

// Collect checks the namespaces (403 protected, 422 missing; SPEC §7.2) and
// lists everything the planner looks at in them. Protected namespaces are
// refused before any read, so the tool never even lists their workloads.
func Collect(ctx context.Context, c kubernetes.Interface, namespaces []string, protected map[string]bool) (Input, error) {
	for _, ns := range namespaces {
		if protected[ns] {
			return Input{}, &Error{Status: http.StatusForbidden, Code: "forbidden_namespace",
				Message: fmt.Sprintf("namespace %s is protected and is never changed", ns), Details: map[string]any{"namespace": ns}}
		}
	}
	var in Input
	for _, ns := range namespaces {
		n, err := c.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return Input{}, &Error{Status: http.StatusUnprocessableEntity, Code: "namespace_not_found",
				Message: fmt.Sprintf("namespace %s does not exist", ns), Details: map[string]any{"namespace": ns}}
		}
		if err != nil {
			return Input{}, fmt.Errorf("get namespace %s: %w", ns, err)
		}
		in.Namespaces = append(in.Namespaces, *n)
		if err := collectNamespace(ctx, c, ns, &in); err != nil {
			return Input{}, err
		}
	}
	return in, nil
}

func collectNamespace(ctx context.Context, c kubernetes.Interface, ns string, in *Input) error {
	opts := metav1.ListOptions{}
	deps, err := c.AppsV1().Deployments(ns).List(ctx, opts)
	if err != nil {
		return fmt.Errorf("list deployments in %s: %w", ns, err)
	}
	in.Deployments = append(in.Deployments, deps.Items...)
	sts, err := c.AppsV1().StatefulSets(ns).List(ctx, opts)
	if err != nil {
		return fmt.Errorf("list statefulsets in %s: %w", ns, err)
	}
	in.StatefulSets = append(in.StatefulSets, sts.Items...)
	dss, err := c.AppsV1().DaemonSets(ns).List(ctx, opts)
	if err != nil {
		return fmt.Errorf("list daemonsets in %s: %w", ns, err)
	}
	in.DaemonSets = append(in.DaemonSets, dss.Items...)
	cjs, err := c.BatchV1().CronJobs(ns).List(ctx, opts)
	if err != nil {
		return fmt.Errorf("list cronjobs in %s: %w", ns, err)
	}
	in.CronJobs = append(in.CronJobs, cjs.Items...)
	jobs, err := c.BatchV1().Jobs(ns).List(ctx, opts)
	if err != nil {
		return fmt.Errorf("list jobs in %s: %w", ns, err)
	}
	in.Jobs = append(in.Jobs, jobs.Items...)
	pods, err := c.CoreV1().Pods(ns).List(ctx, opts)
	if err != nil {
		return fmt.Errorf("list pods in %s: %w", ns, err)
	}
	in.Pods = append(in.Pods, pods.Items...)
	lrs, err := c.CoreV1().LimitRanges(ns).List(ctx, opts)
	if err != nil {
		return fmt.Errorf("list limitranges in %s: %w", ns, err)
	}
	in.LimitRanges = append(in.LimitRanges, lrs.Items...)
	hpas, err := c.AutoscalingV2().HorizontalPodAutoscalers(ns).List(ctx, opts)
	if err != nil {
		return fmt.Errorf("list horizontalpodautoscalers in %s: %w", ns, err)
	}
	in.HPAs = append(in.HPAs, hpas.Items...)
	return nil
}
