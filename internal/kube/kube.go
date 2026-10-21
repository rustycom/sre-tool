// Package kube builds the Kubernetes client and event recorder.
package kube

import (
	"context"
	"errors"
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/events"
)

// ReportingController names the tool on every Event it emits.
const ReportingController = "sre-tool"

// RESTConfig returns the in-cluster config when kubeconfig is empty.
// Otherwise it loads only that file and only the named context, which must
// exist in it: the author's machine has real clusters, so the tool never
// falls back to the current context.
func RESTConfig(kubeconfig, kubeContext string) (*rest.Config, error) {
	if kubeconfig == "" {
		cfg, err := rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("in-cluster config: %w", err)
		}
		return cfg, nil
	}
	if kubeContext == "" {
		return nil, errors.New("a kube context is required with a kubeconfig")
	}
	raw, err := clientcmd.LoadFromFile(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig %s: %w", kubeconfig, err)
	}
	if _, ok := raw.Contexts[kubeContext]; !ok {
		return nil, fmt.Errorf("context %q not found in %s", kubeContext, kubeconfig)
	}
	cfg, err := clientcmd.NewDefaultClientConfig(*raw, &clientcmd.ConfigOverrides{CurrentContext: kubeContext}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("client config for context %q: %w", kubeContext, err)
	}
	return cfg, nil
}

// NewRecorder returns an events.k8s.io/v1 recorder and a function that
// flushes and stops it. Recording stops when ctx is cancelled.
func NewRecorder(ctx context.Context, client kubernetes.Interface) (events.EventRecorder, func(), error) {
	b := events.NewBroadcaster(&events.EventSinkImpl{Interface: client.EventsV1()})
	if err := b.StartRecordingToSinkWithContext(ctx); err != nil {
		return nil, nil, fmt.Errorf("start event recorder: %w", err)
	}
	return b.NewRecorder(scheme.Scheme, ReportingController), b.Shutdown, nil
}
