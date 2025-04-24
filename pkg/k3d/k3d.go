package k3d

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/dag-andersen/argocd-diff-preview/pkg/cluster"
	"github.com/rs/zerolog/log"
)

func (k *K3dCluster) GetName() string {
	return "k3d"
}

// IsInstalled checks if the k3d binary is available in PATH.
func IsInstalled() bool {
	_, err := exec.LookPath("k3d")
	if err != nil {
		log.Debug().Msg("k3d command not found in PATH")
		return false
	}
	return true
}

// CreateCluster creates a new k3d cluster with the given name and options.
func CreateCluster(clusterName, options string, wait time.Duration) error {
	// Check if docker is running first
	if output, err := runCommand("docker", "ps"); err != nil {
		log.Error().Msg("❌ Docker is not running")
		// Include docker command output/err in the returned error for more context
		return fmt.Errorf("docker is not running or docker command failed: %w, output: %s", err, output)
	}

	log.Info().Msg("🚀 Creating cluster...")
	args := []string{"cluster", "create", clusterName, "--wait", "--timeout", wait.String()}

	// Add extra options if provided
	if options != "" {
		// Split the options string by spaces. This handles simple cases.
		// Note: This won't handle options with spaces inside quotes correctly.
		extraOpts := strings.Fields(options)
		args = append(args, extraOpts...)
		log.Info().Msgf("   using extra options: %s", options)
	}

	// Add verbosity flags if needed, e.g., based on verbosity

	_, err := runCommand(args...)
	if err != nil {
		log.Error().Msgf("❌ Failed to create k3d cluster '%s'", clusterName)
		return fmt.Errorf("failed to create k3d cluster '%s': %w", clusterName, err)
	}

	log.Info().Msgf("✅ k3d cluster '%s' created successfully.", clusterName)
	return nil
}

// ClusterExists checks if the k3d cluster with the specified name exists (is running).
func ClusterExists(clusterName string) bool {
	output, err := runCommand("cluster", "list")
	if err != nil {
		log.Warn().Err(err).Msg("Failed to list k3d clusters, assuming cluster does not exist")
		return false
	}
	// Check if the cluster name is in the output list
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for i, line := range lines {
		if i == 0 { // Skip header line
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == clusterName {
			// Basic check, k3d list also shows server/agent counts
			log.Debug().Msgf("k3d cluster '%s' found in list.", clusterName)
			return true // Assume running if listed
		}
	}
	log.Debug().Msgf("k3d cluster '%s' not found in list.", clusterName)
	return false
}

// DeleteCluster deletes the k3d cluster with the specified name.
func DeleteCluster(clusterName string) error {
	if !IsInstalled() {
		log.Warn().Msg("k3d not found, skipping cluster deletion.")
		return nil // Not an error scenario, just skipping
	}
	if !ClusterExists(clusterName) {
		log.Info().Msgf("💨 k3d cluster '%s' not found, skipping deletion.", clusterName)
		return nil // Not an error scenario, just skipping
	}

	log.Info().Msgf("🔥 Deleting k3d cluster '%s'...", clusterName)
	output, err := runCommand("cluster", "delete", clusterName)
	if err != nil {
		log.Error().Msgf("❌ Error deleting k3d cluster '%s': %v", clusterName, err)
		// Return the error instead of just logging
		return fmt.Errorf("failed to delete k3d cluster '%s': %w, output: %s", clusterName, err, output)
	}

	log.Info().Msgf("✅ k3d cluster '%s' deleted successfully.", clusterName)
	return nil
}

// runCommand executes a k3d command and returns its output or error.
func runCommand(args ...string) (string, error) {
	cmd := exec.Command("k3d", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	log.Debug().Msgf("Running command: k3d %s", strings.Join(args, " "))

	err := cmd.Run()
	if err != nil {
		errMsg := stderr.String()
		log.Error().Msgf("❌ Error running k3d command: k3d %s", strings.Join(args, " "))
		if errMsg != "" {
			log.Error().Msgf("Stderr: %s", errMsg)
		}
		// Return the stderr message in the error for better context upstream
		return "", fmt.Errorf("failed to run k3d command: %w, stderr: %s", err, errMsg)
	}
	log.Debug().Msgf("Stdout: %s", stdout.String())
	return stdout.String(), nil
}

// ensure K3dCluster implements cluster.Provider
var _ cluster.Provider = (*K3dCluster)(nil)

// K3dCluster represents a k3d cluster configuration.
type K3dCluster struct {
	Name      string
	Options   string
	wait      time.Duration
	verbosity int
}

// New creates a new K3dCluster instance with default values.
func New(name, options string) *K3dCluster {
	if name == "" {
		name = "argocd-diff-preview" // Default cluster name
	}
	return &K3dCluster{
		Name:      name,
		Options:   options,
		wait:      120 * time.Second, // Default wait time, can be adjusted
		verbosity: 0,                 // Default verbosity
	}
}

// IsInstalled checks if the k3d binary is available in PATH.
func (k *K3dCluster) IsInstalled() bool {
	return IsInstalled()
}

// ClusterExists checks if the configured k3d cluster exists.
func (k *K3dCluster) ClusterExists() bool {
	return ClusterExists(k.Name)
}

// CreateCluster creates the configured k3d cluster.
func (k *K3dCluster) CreateCluster() error {
	return CreateCluster(k.Name, k.Options, k.wait)
}

// DeleteCluster deletes the configured k3d cluster unless keepAlive is true.
func (k *K3dCluster) DeleteCluster(keepAlive bool) {
	if keepAlive {
		log.Info().Msgf("ℹ️ Skipping k3d cluster deletion because keep-cluster-alive is set.")
		return // Return early if keepAlive is true
	}
	// Call the package-level function, handle potential error
	if err := DeleteCluster(k.Name); err != nil {
		// Log the error, as the interface method doesn't return one
		log.Error().Err(err).Msgf("Failed during k3d cluster deletion process for '%s'", k.Name)
	}
}

// GetKubeconfig returns the path to the kubeconfig file for the k3d cluster.
func (k *K3dCluster) GetKubeconfig() (string, error) {
	if !k.IsInstalled() {
		return "", fmt.Errorf("k3d is not installed")
	}
	if !k.ClusterExists() {
		return "", fmt.Errorf("k3d cluster '%s' is not running or does not exist", k.Name)
	}

	log.Debug().Msgf("Getting kubeconfig for k3d cluster '%s'", k.Name)
	// k3d kubeconfig get <clustername> writes to stdout by default
	output, err := runCommand("kubeconfig", "get", k.Name)
	if err != nil {
		// Include the underlying error message which now contains stderr
		return "", fmt.Errorf("failed to get kubeconfig for k3d cluster '%s': %w", k.Name, err)
	}

	// Write the kubeconfig to a temporary file
	tmpFile, err := os.CreateTemp("", "k3d-kubeconfig-*.yaml")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary kubeconfig file: %w", err)
	}
	// No need to defer close here, caller should manage the temp file lifecycle

	if _, err := tmpFile.WriteString(output); err != nil {
		// Attempt to close and remove the temp file if writing fails
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("failed to write kubeconfig to temporary file: %w", err)
	}

	// Close the file handle after successful write before returning the name
	if err := tmpFile.Close(); err != nil {
		// Attempt removal even if close fails, though it might not succeed
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("failed to close temporary kubeconfig file handle: %w", err)
	}

	log.Debug().Msgf("Kubeconfig written to temporary file: %s", tmpFile.Name())
	return tmpFile.Name(), nil
}

// Add the missing import for cluster provider interface
func init() {
	// This forces the compiler check for the interface implementation
	// and ensures the import is present.
	var _ cluster.Provider = (*K3dCluster)(nil)
}
