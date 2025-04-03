# Apoxy Drivers Package

This package provides a common interface for managing Apoxy services (backplane and apiserver) across different driver implementations (Docker, supervisor).

## Overview

The drivers package provides a unified interface for starting and stopping Apoxy services. It supports multiple driver types:

- Docker: Runs services as Docker containers
- Supervisor: Runs services as local processes

And multiple service types:

- Backplane: The Apoxy backplane service
- APIServer: The Apoxy API server

## Usage

```go
// Get a driver for a specific service type
driver, err := drivers.GetDriver("docker", drivers.BackplaneService)
if err != nil {
    // handle error
}

// Start the service
id, err := driver.Start(
    ctx,
    projectID,   // uuid.UUID
    serviceName, // string
    drivers.WithArgs("--some-flag=value"),
)
if err != nil {
    // handle error
}

// Stop the service
driver.Stop(projectID, serviceName)
```

## Driver Types

### Docker Driver

The Docker driver runs services as Docker containers. It handles:

- Container creation and removal
- Network setup
- Image pulling
- Service configuration via command-line arguments

### Supervisor Driver

The Supervisor driver runs services as local processes. It handles:

- Process creation and termination
- Log redirection
- Service configuration via command-line arguments

## Port Forwarding

For Docker-based services, the package includes port forwarding functionality to expose service ports to the host:

```go
fwd, err := drivers.NewPortForwarder(clientConfig, proxyName, replicaName, containerID)
if err != nil {
    // handle error
}

// Start port forwarding
if err := fwd.Run(ctx); err != nil {
    // handle error
}
```
