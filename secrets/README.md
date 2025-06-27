# Secret Management

The `secrets` package provides a unified way to handle secrets within configuration files for Prometheus and its ecosystem components. It allows secrets to be specified inline, loaded from files, or fetched from other sources through a pluggable provider mechanism.

## Concepts

The package is built around a few core concepts:

*   **`SecretField`**: A type used in configuration structs to represent a field that holds a secret. It handles the logic for unmarshaling from different secret sources.
*   **`Provider`**: An interface for fetching secrets from a specific source (e.g., inline string, file on disk). The package comes with built-in providers, and new ones can be registered.
*   **`Manager`**: A component that discovers all `SecretField` instances within a configuration struct, manages their lifecycle, and handles periodic refreshing of secrets.

## How to Use

Using the `secrets` package involves three main steps: defining your configuration struct, initializing the secret manager, and accessing the secret values.

### 1. Define Your Configuration Struct

In your configuration struct, use the `secrets.SecretField` type for any fields that should contain secrets.

```go
package main

import "github.com/prometheus/common/secrets"

type MyConfig struct {
    APIKey    secrets.SecretField `yaml:"api_key"`
    Password  secrets.SecretField `yaml:"password"`
    // ... other config fields
}
```

### 2. Configure Secrets in YAML

Users can then provide secrets in their YAML configuration file.

For simple secrets, an inline string can be used:

```yaml
api_key: "my_super_secret_api_key"
```

To load a secret from a file, use the `file` provider:

```yaml
password:
  file: /path/to/password.txt
```

### 3. Initialize the Secret Manager

After unmarshaling your configuration file into your struct, you must create a `secrets.Manager` to manage the lifecycle of the secrets. The manager is initialized with a pointer to your configuration struct.

```go
import (
    "context"
    "log"

    "github.com/prometheus/common/secrets"
    "gopkg.in/yaml.v2"
)

func main() {
    // Load config from file
    configData := []byte(`
api_key: "my_super_secret_api_key"
password:
  file: /path/to/password.txt
`)
    var cfg MyConfig
    if err := yaml.Unmarshal(configData, &cfg); err != nil {
        log.Fatalf("Error unmarshaling config: %v", err)
    }

    // Create a secret manager. This discovers and manages all SecretFields in cfg.
    // The manager will handle refreshing secrets in the background.
    manager, err := secrets.NewManager(context.Background(), &cfg)
    if err != nil {
        log.Fatalf("Error creating secret manager: %v", err)
    }
    defer manager.Stop()

    // ... your application logic ...

    // Wait for the secrets in cfg to be ready.
    for {
        if ready, err := manager.SecretsReady(&cfg); err != nil {
            log.Fatalf("Error checking secret readiness: %v", err)
        } else if ready {
            break
        }
    }

    // Access the secret value when needed.
    apiKey := cfg.APIKey.Get()
    password := cfg.Password.Get()

    log.Printf("API Key: %s", apiKey)
    log.Printf("Password: %s", password)
}
```

### 4. Accessing Secrets

To get the string value of a secret, simply call the `Get()` method on the `SecretField`.

```go
secretValue := myConfig.APIKey.Get()
```

The manager handles caching and refreshing, so `Get()` will always return the current valid secret.

### Secret Validation

For secrets that can be rotated (e.g., loaded from a file that gets updated), you can provide an optional validation function. This prevents a broken or partially written secret from being loaded into your application after a rotation.

The manager will use the new secret only after your validation function returns `true`, or if no validation has passed.

```go
cfg.Password.SetSecretValidation(myValidator) // myValidator must implement secrets.SecretValidator
```
