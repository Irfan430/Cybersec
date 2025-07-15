# 🛡️ AI-Powered Cybersecurity Risk Simulation Platform

[![CI/CD Pipeline](https://github.com/your-org/cybersec-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/cybersec-platform/actions/workflows/ci.yml)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=cybersec-platform&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=cybersec-platform)
[![Coverage](https://codecov.io/gh/your-org/cybersec-platform/branch/main/graph/badge.svg)](https://codecov.io/gh/your-org/cybersec-platform)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/github/v/release/your-org/cybersec-platform)](https://github.com/your-org/cybersec-platform/releases)

A comprehensive, production-ready cybersecurity platform that combines vulnerability scanning, AI-powered risk assessment, and automated security testing in a modern web-based interface.

## 🌟 Features

### Core Security Features
- **🔍 Vulnerability Scanning**: Custom Nmap/Nikto scripts with real-time progress tracking
- **💥 Brute Force Simulation**: Safe brute force testing for FTP, SSH, HTTP login forms
- **🤖 AI/ML Risk Prediction**: Machine learning models for threat probability assessment
- **📊 Real-time Dashboards**: Interactive charts, heatmaps, and risk visualizations
- **📄 PDF Report Generation**: Downloadable security assessment reports
- **🚨 Smart Alerting**: Telegram & Slack notifications for critical threats

### Platform Features
- **👥 Multi-user Support**: Role-based access control (Admin, Manager, Viewer)
- **🔐 Enterprise Authentication**: JWT + bcrypt with 2FA support
- **🎯 Target Management**: Organize and monitor domains, IPs, and network ranges
- **📈 Analytics & Compliance**: Track security posture and compliance status
- **🎓 Security Training**: Phishing simulation and user awareness training
- **💳 SaaS Billing**: Stripe/PayPal integration for subscription management

### DevSecOps Integration
- **🔧 CI/CD Safe API**: Automated security checks in deployment pipelines
- **🐳 Containerized Deployment**: Docker & Kubernetes ready
- **📊 Metrics & Monitoring**: Comprehensive logging and performance tracking
- **🔄 Auto-scaling**: Horizontal scaling with load balancing

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Backend       │    │   ML Service   │
│   (React)       │◄──►│   (Node.js)     │◄──►│   (FastAPI)     │
│   Port: 3000    │    │   Port: 3000    │    │   Port: 8001    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
         ┌─────────────────┐    ┌─────────────────┐
         │   MongoDB       │    │   Redis Cache   │
         │   Port: 27017   │    │   Port: 6379    │
         └─────────────────┘    └─────────────────┘
```

### Tech Stack

#### Frontend
- **React 18** with TypeScript support
- **Tailwind CSS** for responsive design
- **Vite** for fast development and building
- **React Query** for data fetching and caching
- **Chart.js & ApexCharts** for data visualization
- **Socket.io** for real-time updates

#### Backend
- **Node.js** with Express.js framework
- **MongoDB** for data persistence
- **Redis** for caching and session management
- **JWT** authentication with bcrypt
- **Winston** for structured logging
- **Socket.io** for real-time communication

#### ML Service
- **FastAPI** for high-performance API
- **scikit-learn** for machine learning models
- **TensorFlow/PyTorch** for deep learning
- **NumPy/Pandas** for data processing
- **Redis** for model caching

#### Infrastructure
- **Docker** containerization
- **Kubernetes** orchestration
- **Nginx** reverse proxy
- **GitHub Actions** CI/CD
- **Prometheus** & **Grafana** monitoring

## 🚀 Quick Start

### Prerequisites

- **Node.js** 18+ and npm
- **Python** 3.11+ and pip
- **Docker** and Docker Compose
- **MongoDB** 7.0+
- **Redis** 7.0+

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/cybersec-platform.git
cd cybersec-platform
```

### 2. Environment Setup

```bash
# Copy environment file
cp .env.example .env

# Edit environment variables
nano .env
```

### 3. Install Dependencies

```bash
# Install all dependencies
npm run setup

# Or install individually
cd frontend && npm install
cd ../backend && npm install
cd ../ml-service && pip install -r requirements.txt
```

### 4. Database Setup

```bash
# Start MongoDB and Redis
docker-compose up -d mongodb redis

# Run database migrations
cd backend && npm run migrate
```

### 5. Start Development Services

```bash
# Start all services
npm run dev

# Or start individually
cd frontend && npm run dev    # http://localhost:3000
cd backend && npm run dev     # http://localhost:3000
cd ml-service && uvicorn main:app --reload --port 8001
```

### 6. Access the Platform

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:3000/api
- **ML Service**: http://localhost:8001
- **API Documentation**: http://localhost:8001/docs

## 📖 Usage Guide

### Initial Setup

1. **Register an Account**
   ```bash
   curl -X POST http://localhost:3000/api/auth/register \
     -H "Content-Type: application/json" \
     -d '{
       "email": "admin@example.com",
       "password": "SecurePassword123!",
       "firstName": "John",
       "lastName": "Doe"
     }'
   ```

2. **Login and Get Token**
   ```bash
   curl -X POST http://localhost:3000/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{
       "email": "admin@example.com",
       "password": "SecurePassword123!"
     }'
   ```

### Target Management

3. **Add a Target**
   ```bash
   curl -X POST http://localhost:3000/api/targets \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "Example Website",
       "type": "domain",
       "value": "example.com",
       "environment": "production"
     }'
   ```

### Vulnerability Scanning

4. **Start a Scan**
   ```bash
   curl -X POST http://localhost:3000/api/scans \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "targetId": "TARGET_ID",
       "scanType": "nmap",
       "name": "Full Port Scan"
     }'
   ```

5. **Get Scan Results**
   ```bash
   curl -X GET http://localhost:3000/api/scans/SCAN_ID \
     -H "Authorization: Bearer YOUR_TOKEN"
   ```

### AI Risk Assessment

6. **Get Risk Prediction**
   ```bash
   curl -X POST http://localhost:8001/predict/risk \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "scan_data": {
         "target_type": "domain",
         "scan_type": "nmap",
         "duration": 300,
         "hosts_scanned": 1,
         "open_ports": 5,
         "vulnerabilities": []
       },
       "target_metadata": {}
     }'
   ```

## 🔧 Development

### Project Structure

```
cybersec-platform/
├── frontend/                 # React frontend application
│   ├── src/
│   │   ├── components/      # Reusable UI components
│   │   ├── pages/          # Page components
│   │   ├── hooks/          # Custom React hooks
│   │   ├── services/       # API service functions
│   │   └── contexts/       # React contexts
│   ├── public/             # Static assets
│   └── package.json
├── backend/                 # Node.js backend API
│   ├── src/
│   │   ├── controllers/    # Route controllers
│   │   ├── models/         # Database models
│   │   ├── routes/         # API routes
│   │   ├── middleware/     # Express middleware
│   │   └── services/       # Business logic
│   └── package.json
├── ml-service/             # Python ML microservice
│   ├── models/             # ML model files
│   ├── utils/              # Utility functions
│   ├── main.py             # FastAPI application
│   └── requirements.txt
├── shared/                 # Shared utilities
│   ├── vuln_scanners/      # Vulnerability scanners
│   ├── brute_sim/          # Brute force simulators
│   └── pdf_generator/      # PDF report generator
└── scripts/                # Development scripts
    ├── seed.js             # Database seeding
    └── migrate.js          # Database migrations
```

### Development Commands

```bash
# Frontend
cd frontend
npm run dev          # Start development server
npm run build        # Build for production
npm run test         # Run tests
npm run lint         # Lint code

# Backend
cd backend
npm run dev          # Start development server
npm run test         # Run tests
npm run migrate      # Run database migrations
npm run seed         # Seed database

# ML Service
cd ml-service
uvicorn main:app --reload    # Start development server
pytest                       # Run tests
black .                      # Format code
```

### Testing

```bash
# Run all tests
npm run test

# Run specific test suites
npm run test:frontend
npm run test:backend
cd ml-service && pytest

# Run with coverage
npm run test:coverage
```

### Code Quality

```bash
# Lint all code
npm run lint

# Format code
npm run format

# Security audit
npm audit
safety check  # Python dependencies
```

## 🐳 Docker Deployment

### Development with Docker

```bash
# Build and start all services
docker-compose up --build

# Start in background
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Production Deployment

```bash
# Build production images
docker-compose -f docker-compose.prod.yml build

# Deploy to production
docker-compose -f docker-compose.prod.yml up -d

# Scale services
docker-compose -f docker-compose.prod.yml up -d --scale backend=3
```

## ☸️ Kubernetes Deployment

### Prerequisites

- Kubernetes cluster (1.24+)
- kubectl configured
- Helm 3.0+

### Deploy with Helm

```bash
# Add Helm repository
helm repo add cybersec-platform https://your-org.github.io/cybersec-platform

# Install the chart
helm install cybersec-platform cybersec-platform/cybersec-platform \
  --set mongodb.auth.rootPassword=yourpassword \
  --set redis.auth.password=yourpassword

# Upgrade deployment
helm upgrade cybersec-platform cybersec-platform/cybersec-platform
```

### Manual Deployment

```bash
# Apply Kubernetes manifests
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -n cybersec-platform

# Access services
kubectl port-forward svc/cybersec-platform-frontend 3000:80
```

## 🔒 Security Considerations

### Authentication & Authorization

- JWT tokens with configurable expiration
- Role-based access control (RBAC)
- API key authentication for CI/CD
- Two-factor authentication support
- Session management with Redis

### Data Protection

- Encryption at rest (MongoDB)
- Encryption in transit (TLS/SSL)
- Secure password hashing (bcrypt)
- Input validation and sanitization
- Rate limiting and DDoS protection

### Vulnerability Management

- Regular dependency updates
- Automated security scanning
- OWASP compliance
- Secure coding practices
- Penetration testing

### Monitoring & Auditing

- Comprehensive audit logging
- Real-time alerting
- Performance monitoring
- Security incident response
- Compliance reporting

## 📊 Monitoring & Observability

### Metrics

- Application performance metrics
- Business metrics (scans, users, threats)
- Infrastructure metrics (CPU, memory, disk)
- Custom metrics via Prometheus

### Logging

- Structured logging with Winston
- Centralized log aggregation
- Log rotation and archival
- Search and analysis capabilities

### Alerting

- Real-time threat notifications
- System health alerts
- Performance degradation warnings
- Custom alerting rules

## 🔄 CI/CD Pipeline

### GitHub Actions Workflow

- **Build**: Multi-stage Docker builds
- **Test**: Unit, integration, and security tests
- **Security**: Vulnerability scanning and code analysis
- **Deploy**: Automated deployment to staging/production
- **Monitor**: Post-deployment health checks

### Deployment Strategies

- **Blue-Green**: Zero-downtime deployments
- **Canary**: Gradual rollout with monitoring
- **Rolling**: Progressive instance updates
- **A/B Testing**: Feature flag deployments

## 🤝 Contributing

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

### Code Style

- Follow ESLint rules for JavaScript
- Use Prettier for code formatting
- Follow PEP 8 for Python code
- Write meaningful commit messages
- Add documentation for new features

### Issue Reporting

- Use GitHub Issues for bug reports
- Include reproduction steps
- Provide environment details
- Add relevant logs and screenshots

## 📚 Documentation

### API Documentation

- **OpenAPI/Swagger**: Interactive API documentation
- **Postman Collection**: Ready-to-use API requests
- **SDK Examples**: Code examples in multiple languages

### User Documentation

- **Admin Guide**: System administration
- **User Manual**: End-user documentation
- **Training Materials**: Security awareness content

### Developer Documentation

- **Architecture Guide**: System design and patterns
- **API Reference**: Detailed endpoint documentation
- **Deployment Guide**: Infrastructure setup

## 🔗 Integrations

### Supported Integrations

- **CI/CD**: GitHub Actions, GitLab CI, Jenkins
- **Chat**: Slack, Microsoft Teams, Discord
- **SIEM**: Splunk, ELK Stack, QRadar
- **Ticketing**: Jira, ServiceNow, GitHub Issues
- **Cloud**: AWS, Azure, Google Cloud Platform

### API Endpoints

- **REST API**: Full CRUD operations
- **GraphQL**: Flexible data queries
- **WebSocket**: Real-time updates
- **Webhooks**: Event-driven notifications

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Open Source Libraries**: Thanks to all contributors
- **Security Community**: For vulnerability research and disclosure
- **Beta Testers**: For feedback and testing

## 📞 Support

### Community Support

- **GitHub Issues**: Bug reports and feature requests
- **Discussions**: Community Q&A and ideas
- **Discord**: Real-time chat support

### Enterprise Support

- **Professional Services**: Custom development and integration
- **Priority Support**: SLA-backed technical support
- **Training**: On-site and remote training options

### Contact Information

- **Email**: support@cybersec-platform.com
- **Website**: https://cybersec-platform.com
- **Documentation**: https://docs.cybersec-platform.com
- **Status Page**: https://status.cybersec-platform.com

---

**⭐ If you find this project useful, please consider giving it a star!**

**🔒 Built with security in mind, designed for scale, and optimized for developer experience.**