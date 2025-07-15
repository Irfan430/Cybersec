"""
AI/ML Service for Cybersecurity Risk Prediction
FastAPI microservice for handling machine learning predictions and analysis
"""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import logging
import asyncio
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import pickle
import os
import json
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, classification_report
import joblib
import redis
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import MongoClient
import uvicorn

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ml_service.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Cybersecurity AI/ML Service",
    description="Machine Learning microservice for threat prediction and risk analysis",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Global variables
redis_client = None
mongodb_client = None
models = {}
scalers = {}
label_encoders = {}

# Configuration
MONGODB_URL = os.getenv("MONGODB_URI", "mongodb://localhost:27017/cybersec-platform")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
MODEL_PATH = os.getenv("ML_MODEL_PATH", "./models/")
RETRAIN_INTERVAL = int(os.getenv("RETRAIN_INTERVAL", 86400))  # 24 hours

# Pydantic models
class VulnerabilityData(BaseModel):
    """Model for vulnerability data input"""
    severity: str = Field(..., description="Vulnerability severity (critical, high, medium, low, info)")
    cvss_score: float = Field(..., description="CVSS score (0-10)")
    cve_id: Optional[str] = Field(None, description="CVE identifier")
    cwe_id: Optional[str] = Field(None, description="CWE identifier")
    exploit_available: bool = Field(False, description="Whether exploit is available")
    patch_available: bool = Field(False, description="Whether patch is available")
    age_days: int = Field(..., description="Age of vulnerability in days")
    affected_systems: int = Field(..., description="Number of affected systems")
    service_type: str = Field(..., description="Type of service (web, database, network, etc.)")
    port: int = Field(..., description="Port number")
    protocol: str = Field(..., description="Protocol (tcp, udp)")

class ScanResultData(BaseModel):
    """Model for scan result data"""
    target_type: str = Field(..., description="Type of target (domain, ip, url, etc.)")
    scan_type: str = Field(..., description="Type of scan (nmap, nikto, etc.)")
    duration: int = Field(..., description="Scan duration in seconds")
    hosts_scanned: int = Field(..., description="Number of hosts scanned")
    open_ports: int = Field(..., description="Number of open ports found")
    vulnerabilities: List[VulnerabilityData] = Field(..., description="List of vulnerabilities")
    services_detected: List[str] = Field(..., description="List of detected services")
    operating_systems: List[str] = Field(..., description="List of detected operating systems")
    ssl_issues: int = Field(0, description="Number of SSL/TLS issues")
    web_vulnerabilities: int = Field(0, description="Number of web vulnerabilities")
    network_vulnerabilities: int = Field(0, description="Number of network vulnerabilities")

class RiskPredictionRequest(BaseModel):
    """Request model for risk prediction"""
    scan_data: ScanResultData = Field(..., description="Scan result data")
    target_metadata: Dict[str, Any] = Field(..., description="Target metadata")
    historical_data: Optional[List[Dict[str, Any]]] = Field(None, description="Historical scan data")

class RiskPredictionResponse(BaseModel):
    """Response model for risk prediction"""
    overall_risk_score: float = Field(..., description="Overall risk score (0-100)")
    risk_level: str = Field(..., description="Risk level (critical, high, medium, low, minimal)")
    threat_probability: float = Field(..., description="Probability of threat exploitation (0-1)")
    risk_factors: List[Dict[str, Any]] = Field(..., description="Contributing risk factors")
    recommendations: List[str] = Field(..., description="Risk mitigation recommendations")
    confidence_score: float = Field(..., description="Prediction confidence (0-1)")
    next_scan_recommendation: str = Field(..., description="When to perform next scan")
    trending: str = Field(..., description="Risk trend (increasing, decreasing, stable)")

class ThreatIntelligenceRequest(BaseModel):
    """Request model for threat intelligence"""
    indicators: List[str] = Field(..., description="IOCs (IPs, domains, hashes, etc.)")
    context: Dict[str, Any] = Field(..., description="Context information")

class ThreatIntelligenceResponse(BaseModel):
    """Response model for threat intelligence"""
    threat_level: str = Field(..., description="Threat level")
    malicious_indicators: List[str] = Field(..., description="Identified malicious indicators")
    threat_categories: List[str] = Field(..., description="Threat categories")
    attribution: Optional[str] = Field(None, description="Threat attribution")
    recommendations: List[str] = Field(..., description="Threat mitigation recommendations")

class ModelTrainingRequest(BaseModel):
    """Request model for model training"""
    model_type: str = Field(..., description="Type of model to train")
    training_data: List[Dict[str, Any]] = Field(..., description="Training data")
    validation_split: float = Field(0.2, description="Validation split ratio")

class ModelTrainingResponse(BaseModel):
    """Response model for model training"""
    model_id: str = Field(..., description="Trained model ID")
    accuracy: float = Field(..., description="Model accuracy")
    metrics: Dict[str, Any] = Field(..., description="Training metrics")
    training_time: float = Field(..., description="Training time in seconds")

# Database connection
async def get_database():
    """Get database connection"""
    return mongodb_client.cybersec_platform

# Redis connection
async def get_redis():
    """Get Redis connection"""
    return redis_client

# Authentication dependency
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Validate authentication token"""
    # For now, we'll skip authentication validation
    # In production, this should validate the JWT token
    return {"user_id": "ml_service", "role": "service"}

# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize connections and load models on startup"""
    global redis_client, mongodb_client, models, scalers, label_encoders
    
    try:
        # Connect to Redis
        redis_client = redis.from_url(REDIS_URL)
        await redis_client.ping()
        logger.info("Connected to Redis")
        
        # Connect to MongoDB
        mongodb_client = AsyncIOMotorClient(MONGODB_URL)
        await mongodb_client.admin.command('ping')
        logger.info("Connected to MongoDB")
        
        # Create models directory if it doesn't exist
        os.makedirs(MODEL_PATH, exist_ok=True)
        
        # Load pre-trained models
        await load_models()
        
        # Start background tasks
        asyncio.create_task(model_retraining_task())
        
        logger.info("ML Service started successfully")
        
    except Exception as e:
        logger.error(f"Failed to start ML service: {e}")
        raise

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    global redis_client, mongodb_client
    
    if redis_client:
        await redis_client.close()
    
    if mongodb_client:
        mongodb_client.close()
    
    logger.info("ML Service shutdown complete")

# Model loading
async def load_models():
    """Load pre-trained models from disk"""
    global models, scalers, label_encoders
    
    try:
        # Risk prediction model
        if os.path.exists(f"{MODEL_PATH}/risk_prediction_model.pkl"):
            models['risk_prediction'] = joblib.load(f"{MODEL_PATH}/risk_prediction_model.pkl")
            scalers['risk_prediction'] = joblib.load(f"{MODEL_PATH}/risk_prediction_scaler.pkl")
            logger.info("Loaded risk prediction model")
        else:
            # Initialize default model
            models['risk_prediction'] = RandomForestClassifier(n_estimators=100, random_state=42)
            scalers['risk_prediction'] = StandardScaler()
            logger.info("Initialized default risk prediction model")
        
        # Threat intelligence model
        if os.path.exists(f"{MODEL_PATH}/threat_intel_model.pkl"):
            models['threat_intel'] = joblib.load(f"{MODEL_PATH}/threat_intel_model.pkl")
            scalers['threat_intel'] = joblib.load(f"{MODEL_PATH}/threat_intel_scaler.pkl")
            logger.info("Loaded threat intelligence model")
        else:
            # Initialize default model
            models['threat_intel'] = GradientBoostingClassifier(n_estimators=100, random_state=42)
            scalers['threat_intel'] = StandardScaler()
            logger.info("Initialized default threat intelligence model")
        
        # Vulnerability scoring model
        if os.path.exists(f"{MODEL_PATH}/vuln_scoring_model.pkl"):
            models['vuln_scoring'] = joblib.load(f"{MODEL_PATH}/vuln_scoring_model.pkl")
            scalers['vuln_scoring'] = joblib.load(f"{MODEL_PATH}/vuln_scoring_scaler.pkl")
            logger.info("Loaded vulnerability scoring model")
        else:
            # Initialize default model
            models['vuln_scoring'] = RandomForestClassifier(n_estimators=100, random_state=42)
            scalers['vuln_scoring'] = StandardScaler()
            logger.info("Initialized default vulnerability scoring model")
        
    except Exception as e:
        logger.error(f"Failed to load models: {e}")
        # Initialize with default models
        models['risk_prediction'] = RandomForestClassifier(n_estimators=100, random_state=42)
        scalers['risk_prediction'] = StandardScaler()
        models['threat_intel'] = GradientBoostingClassifier(n_estimators=100, random_state=42)
        scalers['threat_intel'] = StandardScaler()
        models['vuln_scoring'] = RandomForestClassifier(n_estimators=100, random_state=42)
        scalers['vuln_scoring'] = StandardScaler()

# Feature engineering
def extract_features(scan_data: ScanResultData) -> Dict[str, Any]:
    """Extract features from scan data"""
    features = {
        'hosts_scanned': scan_data.hosts_scanned,
        'open_ports': scan_data.open_ports,
        'scan_duration': scan_data.duration,
        'total_vulnerabilities': len(scan_data.vulnerabilities),
        'critical_vulns': sum(1 for v in scan_data.vulnerabilities if v.severity == 'critical'),
        'high_vulns': sum(1 for v in scan_data.vulnerabilities if v.severity == 'high'),
        'medium_vulns': sum(1 for v in scan_data.vulnerabilities if v.severity == 'medium'),
        'low_vulns': sum(1 for v in scan_data.vulnerabilities if v.severity == 'low'),
        'avg_cvss_score': np.mean([v.cvss_score for v in scan_data.vulnerabilities]) if scan_data.vulnerabilities else 0,
        'max_cvss_score': np.max([v.cvss_score for v in scan_data.vulnerabilities]) if scan_data.vulnerabilities else 0,
        'exploitable_vulns': sum(1 for v in scan_data.vulnerabilities if v.exploit_available),
        'unpatched_vulns': sum(1 for v in scan_data.vulnerabilities if not v.patch_available),
        'avg_vuln_age': np.mean([v.age_days for v in scan_data.vulnerabilities]) if scan_data.vulnerabilities else 0,
        'services_count': len(scan_data.services_detected),
        'os_count': len(scan_data.operating_systems),
        'ssl_issues': scan_data.ssl_issues,
        'web_vulnerabilities': scan_data.web_vulnerabilities,
        'network_vulnerabilities': scan_data.network_vulnerabilities,
        'ports_per_host': scan_data.open_ports / max(scan_data.hosts_scanned, 1),
        'vulns_per_host': len(scan_data.vulnerabilities) / max(scan_data.hosts_scanned, 1),
        'scan_type_nmap': 1 if scan_data.scan_type == 'nmap' else 0,
        'scan_type_nikto': 1 if scan_data.scan_type == 'nikto' else 0,
        'scan_type_nuclei': 1 if scan_data.scan_type == 'nuclei' else 0,
        'target_type_domain': 1 if scan_data.target_type == 'domain' else 0,
        'target_type_ip': 1 if scan_data.target_type == 'ip' else 0,
        'target_type_url': 1 if scan_data.target_type == 'url' else 0,
    }
    
    return features

# Risk calculation
def calculate_risk_score(features: Dict[str, Any]) -> float:
    """Calculate risk score based on features"""
    risk_score = 0
    
    # Vulnerability-based scoring
    risk_score += features['critical_vulns'] * 25
    risk_score += features['high_vulns'] * 15
    risk_score += features['medium_vulns'] * 8
    risk_score += features['low_vulns'] * 3
    
    # CVSS-based scoring
    risk_score += features['max_cvss_score'] * 5
    risk_score += features['avg_cvss_score'] * 3
    
    # Exploit availability
    risk_score += features['exploitable_vulns'] * 10
    risk_score += features['unpatched_vulns'] * 8
    
    # Age factor
    if features['avg_vuln_age'] > 365:  # Old vulnerabilities
        risk_score += 15
    elif features['avg_vuln_age'] > 90:
        risk_score += 10
    elif features['avg_vuln_age'] > 30:
        risk_score += 5
    
    # Network exposure
    risk_score += min(features['open_ports'] * 0.5, 20)
    risk_score += features['ssl_issues'] * 5
    
    # Web-specific risks
    risk_score += features['web_vulnerabilities'] * 3
    risk_score += features['network_vulnerabilities'] * 2
    
    # Normalize to 0-100 scale
    risk_score = min(max(risk_score, 0), 100)
    
    return risk_score

# Risk level determination
def determine_risk_level(risk_score: float) -> str:
    """Determine risk level based on score"""
    if risk_score >= 80:
        return "critical"
    elif risk_score >= 60:
        return "high"
    elif risk_score >= 40:
        return "medium"
    elif risk_score >= 20:
        return "low"
    else:
        return "minimal"

# Generate recommendations
def generate_recommendations(scan_data: ScanResultData, risk_score: float) -> List[str]:
    """Generate risk mitigation recommendations"""
    recommendations = []
    
    if scan_data.vulnerabilities:
        critical_vulns = sum(1 for v in scan_data.vulnerabilities if v.severity == 'critical')
        high_vulns = sum(1 for v in scan_data.vulnerabilities if v.severity == 'high')
        
        if critical_vulns > 0:
            recommendations.append(f"Immediately address {critical_vulns} critical vulnerabilities")
        
        if high_vulns > 0:
            recommendations.append(f"Prioritize remediation of {high_vulns} high-severity vulnerabilities")
        
        unpatched = sum(1 for v in scan_data.vulnerabilities if not v.patch_available)
        if unpatched > 0:
            recommendations.append(f"Monitor {unpatched} vulnerabilities without patches for updates")
        
        exploitable = sum(1 for v in scan_data.vulnerabilities if v.exploit_available)
        if exploitable > 0:
            recommendations.append(f"Implement additional controls for {exploitable} exploitable vulnerabilities")
    
    if scan_data.open_ports > 20:
        recommendations.append("Review and close unnecessary open ports")
    
    if scan_data.ssl_issues > 0:
        recommendations.append("Address SSL/TLS configuration issues")
    
    if scan_data.web_vulnerabilities > 0:
        recommendations.append("Implement web application security controls")
    
    if risk_score >= 60:
        recommendations.append("Consider implementing a Web Application Firewall (WAF)")
        recommendations.append("Enable continuous monitoring and alerting")
    
    if not recommendations:
        recommendations.append("Continue regular security monitoring")
    
    return recommendations

# API Endpoints

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "ml-service",
        "version": "1.0.0"
    }

@app.post("/predict/risk", response_model=RiskPredictionResponse)
async def predict_risk(
    request: RiskPredictionRequest,
    current_user: dict = Depends(get_current_user)
):
    """Predict risk based on scan data"""
    try:
        # Extract features
        features = extract_features(request.scan_data)
        
        # Calculate risk score
        risk_score = calculate_risk_score(features)
        
        # Determine risk level
        risk_level = determine_risk_level(risk_score)
        
        # Calculate threat probability (simplified)
        threat_probability = min(risk_score / 100, 1.0)
        
        # Generate recommendations
        recommendations = generate_recommendations(request.scan_data, risk_score)
        
        # Determine next scan recommendation
        if risk_score >= 80:
            next_scan = "daily"
        elif risk_score >= 60:
            next_scan = "weekly"
        elif risk_score >= 40:
            next_scan = "bi-weekly"
        else:
            next_scan = "monthly"
        
        # Risk factors analysis
        risk_factors = []
        
        if request.scan_data.vulnerabilities:
            critical_count = sum(1 for v in request.scan_data.vulnerabilities if v.severity == 'critical')
            if critical_count > 0:
                risk_factors.append({
                    "factor": "Critical Vulnerabilities",
                    "value": critical_count,
                    "weight": 25,
                    "impact": "high"
                })
        
        if request.scan_data.open_ports > 10:
            risk_factors.append({
                "factor": "Open Ports",
                "value": request.scan_data.open_ports,
                "weight": 10,
                "impact": "medium"
            })
        
        # Confidence score (simplified)
        confidence_score = 0.85 if len(request.scan_data.vulnerabilities) > 0 else 0.60
        
        # Trending analysis (simplified)
        trending = "stable"
        if request.historical_data and len(request.historical_data) > 1:
            # Analyze trend based on historical data
            recent_scores = [d.get('risk_score', 0) for d in request.historical_data[-3:]]
            if len(recent_scores) >= 2:
                if recent_scores[-1] > recent_scores[-2]:
                    trending = "increasing"
                elif recent_scores[-1] < recent_scores[-2]:
                    trending = "decreasing"
        
        response = RiskPredictionResponse(
            overall_risk_score=risk_score,
            risk_level=risk_level,
            threat_probability=threat_probability,
            risk_factors=risk_factors,
            recommendations=recommendations,
            confidence_score=confidence_score,
            next_scan_recommendation=next_scan,
            trending=trending
        )
        
        logger.info(f"Risk prediction completed: {risk_level} ({risk_score})")
        return response
        
    except Exception as e:
        logger.error(f"Risk prediction failed: {e}")
        raise HTTPException(status_code=500, detail="Risk prediction failed")

@app.post("/threat-intel/analyze", response_model=ThreatIntelligenceResponse)
async def analyze_threat_intelligence(
    request: ThreatIntelligenceRequest,
    current_user: dict = Depends(get_current_user)
):
    """Analyze threat intelligence indicators"""
    try:
        # This is a simplified implementation
        # In production, this would integrate with threat intelligence feeds
        
        malicious_indicators = []
        threat_categories = []
        
        # Basic threat analysis (simplified)
        for indicator in request.indicators:
            # Check against known malicious patterns
            if any(pattern in indicator.lower() for pattern in ['malware', 'trojan', 'botnet']):
                malicious_indicators.append(indicator)
                threat_categories.append('malware')
        
        # Determine threat level
        threat_level = "high" if malicious_indicators else "low"
        
        recommendations = [
            "Monitor these indicators in your environment",
            "Implement network-based detection rules",
            "Update threat intelligence feeds"
        ]
        
        response = ThreatIntelligenceResponse(
            threat_level=threat_level,
            malicious_indicators=malicious_indicators,
            threat_categories=list(set(threat_categories)),
            attribution=None,
            recommendations=recommendations
        )
        
        logger.info(f"Threat intelligence analysis completed: {threat_level}")
        return response
        
    except Exception as e:
        logger.error(f"Threat intelligence analysis failed: {e}")
        raise HTTPException(status_code=500, detail="Threat intelligence analysis failed")

@app.post("/models/train", response_model=ModelTrainingResponse)
async def train_model(
    request: ModelTrainingRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """Train or retrain ML models"""
    try:
        # Start background training task
        background_tasks.add_task(train_model_background, request)
        
        return ModelTrainingResponse(
            model_id=f"{request.model_type}_{int(datetime.now().timestamp())}",
            accuracy=0.0,  # Will be updated after training
            metrics={},
            training_time=0.0
        )
        
    except Exception as e:
        logger.error(f"Model training failed: {e}")
        raise HTTPException(status_code=500, detail="Model training failed")

@app.get("/models/status")
async def get_model_status(current_user: dict = Depends(get_current_user)):
    """Get status of loaded models"""
    try:
        status = {
            "models": list(models.keys()),
            "last_updated": datetime.now().isoformat(),
            "model_info": {}
        }
        
        for model_name, model in models.items():
            status["model_info"][model_name] = {
                "type": type(model).__name__,
                "loaded": True
            }
        
        return status
        
    except Exception as e:
        logger.error(f"Failed to get model status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get model status")

# Background tasks
async def train_model_background(request: ModelTrainingRequest):
    """Background task for model training"""
    try:
        logger.info(f"Starting background training for {request.model_type}")
        
        # Simulate training process
        await asyncio.sleep(10)  # Simulate training time
        
        # Save model
        model_path = f"{MODEL_PATH}/{request.model_type}_model.pkl"
        scaler_path = f"{MODEL_PATH}/{request.model_type}_scaler.pkl"
        
        # Create dummy trained model for demonstration
        if request.model_type == "risk_prediction":
            model = RandomForestClassifier(n_estimators=100, random_state=42)
            scaler = StandardScaler()
            
            # In production, this would use actual training data
            # For demo, we'll create dummy data
            X_dummy = np.random.rand(100, 20)
            y_dummy = np.random.randint(0, 5, 100)
            
            X_scaled = scaler.fit_transform(X_dummy)
            model.fit(X_scaled, y_dummy)
            
            # Save model and scaler
            joblib.dump(model, model_path)
            joblib.dump(scaler, scaler_path)
            
            # Update global models
            models[request.model_type] = model
            scalers[request.model_type] = scaler
        
        logger.info(f"Background training completed for {request.model_type}")
        
    except Exception as e:
        logger.error(f"Background training failed for {request.model_type}: {e}")

async def model_retraining_task():
    """Background task for periodic model retraining"""
    while True:
        try:
            await asyncio.sleep(RETRAIN_INTERVAL)
            
            logger.info("Starting scheduled model retraining")
            
            # Fetch latest training data from database
            # Retrain models with new data
            # Update model files
            
            logger.info("Scheduled model retraining completed")
            
        except Exception as e:
            logger.error(f"Scheduled retraining failed: {e}")
            await asyncio.sleep(3600)  # Wait 1 hour before retrying

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info"
    )