# CI/CD Pipeline

## Overview

This repository contains a CI/CD pipeline for automating security scanning, testing, building, and deploying an application using GitHub Actions. The pipeline includes the following stages:

1. **Security Scanning**: Performs various security checks on the codebase.
2. **Build and Test**: Installs dependencies, runs tests, and builds the application.
3. **Deploy to Staging**: Deploys the application to the staging environment for further testing.
4. **Deploy to Production**: Deploys the application to the production environment after passing all previous stages.

---

## Workflow Triggers

This pipeline is triggered on:

- Pushes to the `main` branch.
- Pull requests targeting the `main` branch.

---

## Jobs

### 1. Security Scanning

Performs the following security checks:

- **Commit Signature Validation**: Ensures commits are signed.
- **Secret Scanning**: Detects hardcoded secrets using Gitleaks.
- **Static Application Security Testing (SAST)**: Analyzes code for vulnerabilities using CodeQL.
- **Dependency Scanning**: Checks dependencies for known vulnerabilities using `safety`.
- **Infrastructure-as-Code Scanning**: Analyzes Terraform configurations with `tfsec`.

**Code:**

```yaml
jobs:
  security-scan:
    name: Security Scanning
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Validate commit signatures
        run: |
          git log --show-signature -n 10

      - name: Secret scanning
        uses: gitleaks/gitleaks-action@latest

      - name: SAST scanning
        uses: github/codeql-action/analyze@latest
        with:
          languages: python, javascript

      - name: Dependency scanning
        run: |
          python -m pip install safety
          safety check -r app/requirements.txt --json > safety-report.json

      - name: Infrastructure-as-Code scanning
        uses: aquasecurity/tfsec-action@latest
        with:
          soft_fail: false
```

### 2. Build and Test

This stage:

- Sets up Python and installs dependencies.
- Runs unit tests with `pytest`.
- Performs security analysis with `bandit`.
- Builds a Docker image.
- Scans the Docker image for vulnerabilities using Trivy.

**Code:**

```yaml
jobs:
  build:
    name: Build and Test
    needs: security-scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.9"
          cache: "pip"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r app/requirements.txt pytest pytest-cov bandit

      - name: Run tests
        run: |
          pytest --cov=app tests/
          bandit -r app/

      - name: Build Docker image
        run: |
          docker build -t app:${{ github.sha }} app/
```

### 3. Deploy to Staging

This stage:

- Downloads the built Docker image.
- Configures AWS credentials.
- Deploys the application to a Kubernetes staging environment using `kubectl`.
- Performs Dynamic Application Security Testing (DAST) using OWASP ZAP.

**Code:**

```yaml
jobs:
  deploy-staging:
    name: Deploy to Staging
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: staging
      url: ${{ vars.STAGING_API_BASE_URL }}
    steps:
      - name: Deploy to ECS
        run: |
          kubectl apply -f kubernetes/staging/deployment.yaml
          kubectl rollout status deployment/app-deployment -n staging
```

### 4. Deploy to Production

This stage:

- Deploys the application to the production Kubernetes cluster.
- Runs smoke tests to verify deployment.
- Sends a notification to Slack upon successful deployment.

**Code:**

```yaml
jobs:
  deploy-production:
    name: Deploy to Production
    needs: deploy-staging
    runs-on: ubuntu-latest
    environment:
      name: production
      url: ${{ vars.API_BASE_URL }}
    steps:
      - name: Deploy to production
        run: |
          kubectl apply -f kubernetes/production/deployment.yaml
          kubectl rollout status deployment/app-deployment -n production

      - name: Send deployment notification
        uses: slackapi/slack-github-action@latest
        with:
          payload: |
            {
              "text": "Deployment to production completed successfully: ${{ github.repository }}@${{ github.sha }}"
            }
```

---

## Environment Variables

The following environment variables are required for deployment:

| Variable               | Description                           |
| ---------------------- | ------------------------------------- |
| `AWS_ROLE_TO_ASSUME`   | IAM role to assume for AWS operations |
| `AWS_REGION`           | AWS region for deployment             |
| `STAGING_API_BASE_URL` | Staging environment API base URL      |
| `API_BASE_URL`         | Production API base URL               |
| `SLACK_WEBHOOK_URL`    | Webhook URL for Slack notifications   |

---

## Deployment

### Deploying to Staging

The application is automatically deployed to staging when changes are pushed to `main`.

### Deploying to Production

Production deployment is triggered after staging deployment succeeds.

---

## Security Considerations

- Commits must be signed.
- Secrets are scanned before merging.
- Dependencies are regularly checked for vulnerabilities.
- Docker images are scanned for security issues before deployment.

---

## Notifications

- A Slack notification is sent upon successful production deployment.
- Errors and failures will be visible in GitHub Actions logs.

---

## Future Improvements

- Implement auto-scaling for production.
- Add more test coverage.
- Enhance logging and monitoring.

---

## License

This project is licensed under the MIT License.
