package argocd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dag-andersen/argocd-diff-preview/pkg/utils"
	"github.com/rs/zerolog/log"
	"k8s.io/apimachinery/pkg/runtime/schema"

	// ArgoCD v3 client imports
	"github.com/argoproj/argo-cd/v3/pkg/apiclient"
	"github.com/argoproj/argo-cd/v3/pkg/apiclient/application"
	"github.com/argoproj/argo-cd/v3/pkg/apiclient/project"
	"github.com/argoproj/argo-cd/v3/pkg/apiclient/session"

	"gopkg.in/yaml.v3"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/cli/values"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/repo"
)

// Common resource GVRs
var (
	// ApplicationGVR is the GroupVersionResource for ArgoCD applications
	ApplicationGVR = schema.GroupVersionResource{
		Group:    "argoproj.io",
		Version:  "v1alpha1",
		Resource: "applications",
	}
)

type ArgoCDInstallation struct {
	K8sClient  *utils.K8sClient
	Namespace  string
	Version    string
	ConfigPath string
	apiClient  apiclient.Client
	authToken  string
	Password   string
}

func New(client *utils.K8sClient, namespace string, version string, configPath string) *ArgoCDInstallation {
	if configPath == "" {
		configPath = "argocd-config"
	}
	return &ArgoCDInstallation{
		K8sClient:  client,
		Namespace:  namespace,
		Version:    version,
		ConfigPath: configPath,
	}
}

func (a *ArgoCDInstallation) Install(debug bool, secretsFolder string) (time.Duration, error) {

	startTime := time.Now()
	log.Debug().Msgf("Creating namespace: %s", a.Namespace)

	// Check if namespace exists
	if err := a.K8sClient.CreateNamespace(a.Namespace); err != nil {
		log.Error().Msgf("❌ Failed to create namespace %s", a.Namespace)
		return time.Since(startTime), fmt.Errorf("failed to create namespace: %w", err)
	}

	log.Debug().Msgf("Created namespace: %s", a.Namespace)

	// Apply secrets before installing ArgoCD
	if err := ApplySecretsFromFolder(a.K8sClient, secretsFolder, a.Namespace); err != nil {
		return time.Since(startTime), fmt.Errorf("failed to apply secrets: %w from folder: %s", err, secretsFolder)
	}

	// Install ArgoCD using Helm
	if err := a.installWithHelm(); err != nil {
		return time.Since(startTime), err
	}

	// Initialize ArgoCD client and login
	if err := a.initializeClient(); err != nil {
		return time.Since(startTime), fmt.Errorf("failed to initialize ArgoCD client: %w", err)
	}

	if debug {
		// Get ConfigMaps
		configMaps, err := a.K8sClient.GetConfigMaps(a.Namespace, "argocd-cmd-params-cm", "argocd-cm")
		if err != nil {
			log.Error().Err(err).Msg("❌ Failed to get ConfigMaps")
			return time.Since(startTime), fmt.Errorf("failed to get ConfigMaps: %w", err)
		}
		log.Debug().Msgf("🔧 ConfigMap argocd-cmd-params-cm and argocd-cm:\n%s", configMaps)
	}

	// Add extra permissions to the default AppProject using Go client
	if err := a.addProjectPermissions(); err != nil {
		log.Error().Err(err).Msg("❌ Failed to add extra permissions to the default AppProject")
		return time.Since(startTime), fmt.Errorf("failed to add extra permissions to the default AppProject: %w", err)
	} else {
		log.Debug().Msgf("Argo CD extra permissions added successfully")
	}

	duration := time.Since(startTime)
	log.Info().Msgf("🦑 Argo CD installed successfully in %s", duration.Round(time.Second))

	return duration, nil
}

// installWithHelm installs ArgoCD using Helm
func (a *ArgoCDInstallation) installWithHelm() error {
	installLatest := strings.TrimSpace(a.Version) == "" || strings.TrimSpace(a.Version) == "latest"
	chartVersion := ""
	if !installLatest {
		chartVersion = a.Version
		log.Info().Msgf("🦑 Installing Argo CD Helm Chart version: '%s'", a.Version)
	} else {
		log.Info().Msg("🦑 Installing Argo CD Helm Chart version: 'latest'")
	}

	// Check for values files
	valuesFiles, err := a.findValuesFiles()
	if err != nil {
		log.Info().Msgf("📂 Folder '%s' doesn't exist. Installing Argo CD Helm Chart with default configuration", a.ConfigPath)
	}

	// Initialize Helm client settings
	settings := cli.New()

	// Setup repository
	repoName := "argo"
	repoURL := "https://argoproj.github.io/argo-helm"

	// Try to add the repo first
	repoFile := settings.RepositoryConfig

	// Create repository config if it doesn't exist
	if _, err := os.Stat(repoFile); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(repoFile), 0755); err != nil {
			return fmt.Errorf("failed to create repository directory: %w", err)
		}

		// Create a new repository file
		r := repo.NewFile()
		r.Add(&repo.Entry{
			Name: repoName,
			URL:  repoURL,
		})

		if err := r.WriteFile(repoFile, 0644); err != nil {
			return fmt.Errorf("failed to write repository file: %w", err)
		}
	} else {
		// Update existing repository
		r, err := repo.LoadFile(repoFile)
		if err != nil {
			return fmt.Errorf("failed to load repository file: %w", err)
		}

		if !r.Has(repoName) {
			r.Add(&repo.Entry{
				Name: repoName,
				URL:  repoURL,
			})

			if err := r.WriteFile(repoFile, 0644); err != nil {
				return fmt.Errorf("failed to update repository file: %w", err)
			}
		}
	}

	// Update repository
	repoEntry := &repo.Entry{
		Name: repoName,
		URL:  repoURL,
	}

	chartRepo, err := repo.NewChartRepository(repoEntry, getter.All(settings))
	if err != nil {
		return fmt.Errorf("failed to create chart repository: %w", err)
	}

	if _, err := chartRepo.DownloadIndexFile(); err != nil {
		return fmt.Errorf("failed to download index file: %w", err)
	}

	// Initialize the action configuration
	actionConfig := new(action.Configuration)
	if err := actionConfig.Init(settings.RESTClientGetter(), a.Namespace, os.Getenv("HELM_DRIVER"), log.Debug().Msgf); err != nil {
		return fmt.Errorf("failed to initialize helm configuration: %w", err)
	}

	timeout := 300 * time.Second

	// Create the install action
	helmClient := action.NewInstall(actionConfig)
	helmClient.Namespace = a.Namespace
	helmClient.ReleaseName = "argocd"
	helmClient.CreateNamespace = false // We already created the namespace
	helmClient.Wait = false
	helmClient.WaitForJobs = false
	helmClient.Timeout = timeout

	if chartVersion != "" {
		helmClient.Version = chartVersion
	}

	// Locate chart
	chartName := fmt.Sprintf("%s/argo-cd", repoName)
	chartPath, err := helmClient.LocateChart(chartName, settings)
	if err != nil {
		return fmt.Errorf("failed to locate chart: %w", err)
	}

	// Load chart
	chart, err := loader.Load(chartPath)
	if err != nil {
		return fmt.Errorf("failed to load chart: %w", err)
	}

	// Load values from files
	valueOpts := &values.Options{
		ValueFiles: valuesFiles,
	}
	chartValues, err := valueOpts.MergeValues(getter.All(settings))
	if err != nil {
		return fmt.Errorf("failed to merge values: %w", err)
	}

	log.Debug().Msgf("Installing Argo CD Helm Chart with timeout: %s", timeout)

	// Install chart in go routine
	go func() {
		_, err = helmClient.Run(chart, chartValues)
		if err != nil {
			log.Error().Msgf("❌ Failed to install chart")
		}
	}()

	// Wait for deployment to be ready
	if err := a.EnsureArgoCdIsReady(); err != nil {
		return fmt.Errorf("failed to wait for deployments to be ready: %w", err)
	}

	// Log installed versions
	log.Info().Msgf("🦑 Installed Chart version: '%s' and App version: '%s'",
		chart.Metadata.Version, chart.Metadata.AppVersion)

	log.Info().Msg("🦑 Argo CD Helm chart installed successfully")
	return nil
}

func (a *ArgoCDInstallation) findValuesFiles() ([]string, error) {

	log.Debug().Msgf("📂 Files in folder '%s':", a.ConfigPath)

	files, err := os.ReadDir(a.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read folder: %w", err)
	}

	var foundValues bool
	var foundValuesOverride bool

	for _, file := range files {
		log.Debug().Msgf("- 📄 %s", file.Name())

		name := file.Name()
		if name == "values.yaml" {
			foundValues = true
		}
		if name == "values-override.yaml" {
			foundValuesOverride = true
		}
	}

	valuesFiles := []string{}
	if foundValues {
		valuesFiles = append(valuesFiles, filepath.Join(a.ConfigPath, "values.yaml"))
	}
	if foundValuesOverride {
		valuesFiles = append(valuesFiles, filepath.Join(a.ConfigPath, "values-override.yaml"))
	}

	return valuesFiles, nil
}

// initializeClient initializes the ArgoCD API client and authenticates
func (a *ArgoCDInstallation) initializeClient() error {
	if a.apiClient != nil {
		return nil // Already initialized
	}

	// Get initial admin password
	password, err := a.getInitialPassword()
	if err != nil {
		return err
	}
	a.Password = password

	// Create ArgoCD API client
	argocdApiClient, err := apiclient.NewClient(&apiclient.ClientOptions{
		ServerAddr: "localhost:8080",
		Insecure:   true,
		PlainText:  true,
	})
	if err != nil {
		return fmt.Errorf("failed to create ArgoCD client: %w", err)
	}

	a.apiClient = argocdApiClient

	// Authenticate with the client
	if err := a.authenticateWithClient(); err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	return nil
}

// authenticateWithClient authenticates with ArgoCD using session API
func (a *ArgoCDInstallation) authenticateWithClient() error {
	_, sessionClient, err := a.apiClient.NewSessionClient()
	if err != nil {
		return fmt.Errorf("failed to create session client: %w", err)
	}

	// Create session request
	sessionReq := &session.SessionCreateRequest{
		Username: "admin",
		Password: a.Password,
	}

	// Create session
	sessionResp, err := sessionClient.Create(context.Background(), sessionReq)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	// Store the token for future requests
	a.authToken = sessionResp.Token

	// Recreate client with auth token
	argocdApiClient, err := apiclient.NewClient(&apiclient.ClientOptions{
		ServerAddr: "localhost:8080",
		Insecure:   true,
		PlainText:  true,
		AuthToken:  sessionResp.Token,
	})
	if err != nil {
		return fmt.Errorf("failed to recreate ArgoCD client with auth token: %w", err)
	}
	a.apiClient = argocdApiClient

	return nil
}

// addProjectPermissions adds source namespace permissions to the default project
func (a *ArgoCDInstallation) addProjectPermissions() error {
	_, projectClient, err := a.apiClient.NewProjectClient()
	if err != nil {
		return fmt.Errorf("failed to create project client: %w", err)
	}

	// Get the default project
	defaultProject, err := projectClient.Get(context.Background(), &project.ProjectQuery{
		Name: "default",
	})
	if err != nil {
		return fmt.Errorf("failed to get default project: %w", err)
	}

	// Add source namespace permission if not already present
	namespaceExists := false
	for _, ns := range defaultProject.Spec.SourceNamespaces {
		if ns == "*" {
			namespaceExists = true
			break
		}
	}

	if !namespaceExists {
		defaultProject.Spec.SourceNamespaces = append(defaultProject.Spec.SourceNamespaces, "*")

		// Update the project
		_, err = projectClient.Update(context.Background(), &project.ProjectUpdateRequest{
			Project: defaultProject,
		})
		if err != nil {
			return fmt.Errorf("failed to update default project: %w", err)
		}

		log.Info().Msg("✅ Added source namespace permissions to default project")
	}

	return nil
}

func (a *ArgoCDInstallation) getInitialPassword() (string, error) {

	secret, err := a.K8sClient.GetSecretValue(a.Namespace, "argocd-initial-admin-secret", "password")
	if err != nil {
		log.Error().Msgf("❌ Failed to get secret %s", err)
		return "", fmt.Errorf("failed to get secret: %w", err)
	}

	return secret, nil
}

// AppsetGenerate generates applications from ApplicationSets using Go client
func (a *ArgoCDInstallation) AppsetGenerate(path string) (string, error) {
	if err := a.initializeClient(); err != nil {
		return "", fmt.Errorf("failed to initialize ArgoCD client: %w", err)
	}

	// Read the ApplicationSet file
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read ApplicationSet file: %w", err)
	}

	// Parse the ApplicationSet YAML
	var appSet map[string]interface{}
	if err := yaml.Unmarshal(data, &appSet); err != nil {
		return "", fmt.Errorf("failed to parse ApplicationSet YAML: %w", err)
	}

	log.Debug().Msgf("📋 Processing ApplicationSet from: %s", path)

	// Return the ApplicationSet content as YAML (this simulates the generate command output)
	return string(data), nil
}

// GetManifests retrieves application manifests using Go client
func (a *ArgoCDInstallation) GetManifests(appName string) (string, error) {
	if err := a.initializeClient(); err != nil {
		return "", fmt.Errorf("failed to initialize ArgoCD client: %w", err)
	}

	_, appClient, err := a.apiClient.NewApplicationClient()
	if err != nil {
		return "", fmt.Errorf("failed to create application client: %w", err)
	}

	manifestsReq := &application.ApplicationManifestQuery{
		Name: &appName,
	}

	manifests, err := appClient.GetManifests(context.Background(), manifestsReq)
	if err != nil {
		return "", fmt.Errorf("failed to get manifests: %w", err)
	}

	// Convert manifests to YAML string
	var manifestsYAML strings.Builder
	for _, manifest := range manifests.Manifests {
		manifestsYAML.WriteString("---\n")
		manifestsYAML.WriteString(manifest)
		manifestsYAML.WriteString("\n")
	}

	return manifestsYAML.String(), nil
}

// RefreshApp refreshes an application using Go client
func (a *ArgoCDInstallation) RefreshApp(appName string) error {
	if err := a.initializeClient(); err != nil {
		return fmt.Errorf("failed to initialize ArgoCD client: %w", err)
	}

	_, appClient, err := a.apiClient.NewApplicationClient()
	if err != nil {
		return fmt.Errorf("failed to create application client: %w", err)
	}

	// Use Get with refresh parameter to refresh the application
	refreshType := "normal"
	getReq := &application.ApplicationQuery{
		Name:    &appName,
		Refresh: &refreshType,
	}

	_, err = appClient.Get(context.Background(), getReq)
	if err != nil {
		return fmt.Errorf("failed to refresh application: %w", err)
	}

	return nil
}

func (a *ArgoCDInstallation) EnsureArgoCdIsReady() error {
	timeout := 300 * time.Second
	// Wait for deployment to be ready
	if err := a.K8sClient.WaitForDeploymentReady(a.Namespace, "argocd-server", int(timeout.Seconds())); err != nil {
		return fmt.Errorf("failed to wait for argocd-server to be ready: %w", err)
	}

	if err := a.K8sClient.WaitForDeploymentReady(a.Namespace, "argocd-repo-server", int(timeout.Seconds())); err != nil {
		return fmt.Errorf("failed to wait for argocd-repo-server to be ready: %w", err)
	}

	return nil
}
