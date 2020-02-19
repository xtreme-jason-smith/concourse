package kubernetes

import (
	"fmt"
	"path/filepath"

	"code.cloudfoundry.org/garden"
	"github.com/concourse/concourse/atc/db"
	"github.com/concourse/concourse/atc/worker"
	"github.com/concourse/concourse/atc/worker/kubernetes/backend"
	"github.com/hashicorp/go-multierror"
)

func (k Kubernetes) findOrCreateContainer(
	owner db.ContainerOwner,
	containerMetadata db.ContainerMetadata,
	containerSpec worker.ContainerSpec,
) (*backend.Container, error) {
	w, found, err := k.wf.GetWorker("k8s")
	if err != nil {
		return nil, fmt.Errorf("get worker: %w")
	}

	if !found {
		return nil, fmt.Errorf("no worker found")
	}

	creating, created, err := w.FindContainer(owner)
	if err != nil {
		return nil, fmt.Errorf("find container: %w")
	}

	var handle string

	switch {
	case creating != nil:
		handle = creating.Handle()
	case created != nil:
		handle = created.Handle()
	default:
		creating, err = w.CreateContainer(
			owner,
			containerMetadata,
		)
		if err != nil {
			return nil, fmt.Errorf("creating db container: %w", err)
		}

		handle = creating.Handle()
	}

	// TODO tell that it's a not found
	container, err := k.be.Lookup(handle)
	if err != nil {
		_, ok := err.(garden.ContainerNotFoundError)
		if !ok {
			return nil, fmt.Errorf("pod lookup: %w", err)
		}
	}

	if created != nil {
		if container == nil {
			// how come?
			return nil, fmt.Errorf("couldn't find pod of container marked as created: %s", handle)
		}
	}

	if container == nil {
		// figure the image out
		imageUri, err := k.fetchImageForContainer(containerSpec, w, creating)
		if err != nil {
			err = fmt.Errorf("fetch img for container: %w", err)

			_, transitionErr := creating.Failed() // TODO wrap this .. somehow?
			// would be nice to not miss this potential err
			// ps.: we should do this `ir err, FAILED + capture err`
			// everywhere here.

			if transitionErr != nil {
				err = multierror.Append(transitionErr, err)
			}

			return nil, err
		}

		inputs := make(map[string]string, len(containerSpec.ArtifactByPath))
		inputSources := make(map[string]string, len(containerSpec.ArtifactByPath))

		for dest, artifact := range containerSpec.ArtifactByPath {
			artf := UnmarshalPodArtifact(artifact.ID())
			uri := "http://" + artf.Ip + ":7788/volumes/" + artf.Handle + "/stream-out"
			name := filepath.Base(dest)

			inputs[name] = dest
			inputSources[uri] = dest
		}

		podDefinition := backend.Pod(
			backend.WithBase(handle),
			backend.WithBaggageclaim(), // could be noop if no outputs
			backend.WithInputsFetcher(inputSources,
				backend.WithInputs(inputs),
			),
			backend.WithMain(imageUri,
				backend.WithEnv(containerSpec.Env),
				backend.WithDir(containerSpec.Dir),
				backend.WithOutputs(containerSpec.Outputs),
				backend.WithInputs(inputs),
				backend.WithBaggageclaimVolumeMount(),
			),
		)

		// create the pod
		container, err = k.be.Create(handle, podDefinition)
		if err != nil {
			return nil, fmt.Errorf("creating container: %w", err)
		}

		created, err = creating.Created()
		if err != nil {
			return nil, fmt.Errorf("transitioning creating to created: %w", err)
		}
	}

	return container, nil
}
