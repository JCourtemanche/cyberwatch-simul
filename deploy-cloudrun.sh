#!/bin/bash
# Cloud Run deployment script for the Cyberwatch API simulator.
# Usage: bash deploy-cloudrun.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
REGION="europe-west1"
SERVICE_NAME="cyberwatch-simulator"
REPO_NAME="cyberwatch-simulator"

CW_ACCESS_KEY="${CW_ACCESS_KEY:-cyberwatch-access-key}"
CW_SECRET_KEY="${CW_SECRET_KEY:-cyberwatch-secret-key}"

echo -e "${GREEN}=== Cloud Run deployment — Cyberwatch Simulator ===${NC}\n"
echo -e "${YELLOW}Project:${NC} $PROJECT_ID"
echo -e "${YELLOW}Region:${NC}  $REGION"
echo -e "${YELLOW}Service:${NC} $SERVICE_NAME"
echo ""

echo -e "${YELLOW}[1/6] Enabling APIs...${NC}"
gcloud services enable run.googleapis.com
gcloud services enable cloudbuild.googleapis.com
gcloud services enable artifactregistry.googleapis.com
echo -e "${GREEN}✓ APIs enabled${NC}\n"

echo -e "${YELLOW}[2/6] Configuring Artifact Registry...${NC}"
REPO_EXISTS=$(gcloud artifacts repositories list \
  --location=$REGION \
  --filter="name:$REPO_NAME" \
  --format="value(name)" 2>/dev/null)

if [ -z "$REPO_EXISTS" ]; then
  gcloud artifacts repositories create $REPO_NAME \
    --repository-format=docker \
    --location=$REGION \
    --description="Cyberwatch API Simulator images" \
    --quiet
  echo -e "${GREEN}✓ Repository created${NC}"
else
  echo -e "${GREEN}✓ Repository already exists${NC}"
fi
echo ""

echo -e "${YELLOW}[3/6] Checking Dockerfile...${NC}"
if [ ! -f "deployment/Dockerfile" ]; then
    echo -e "${RED}ERROR: Dockerfile not found${NC}"
    echo "Please run this script from the cyberwatch-simul repository root."
    exit 1
fi
echo -e "${GREEN}✓ Dockerfile found${NC}\n"

echo -e "${YELLOW}[4/6] Building Docker image...${NC}"
echo "This may take 2-3 minutes..."
gcloud builds submit --config cloudbuild.yaml

IMAGE_PATH="${REGION}-docker.pkg.dev/$PROJECT_ID/$REPO_NAME/cyberwatch-simulator:latest"
echo -e "${GREEN}✓ Image built: $IMAGE_PATH${NC}\n"

echo -e "${YELLOW}[5/6] Deploying to Cloud Run...${NC}"
gcloud run deploy $SERVICE_NAME \
  --image $IMAGE_PATH \
  --platform managed \
  --region $REGION \
  --allow-unauthenticated \
  --memory 512Mi \
  --cpu 1 \
  --timeout 300 \
  --min-instances 0 \
  --max-instances 2 \
  --set-env-vars "CYBERWATCH_ACCESS_KEY=${CW_ACCESS_KEY},CYBERWATCH_SECRET_KEY=${CW_SECRET_KEY},DEBUG=False"

echo -e "${YELLOW}[6/6] Configuring public access...${NC}"
gcloud run services add-iam-policy-binding $SERVICE_NAME \
  --region=$REGION \
  --member=allUsers \
  --role=roles/run.invoker \
  --project=$PROJECT_ID \
  --quiet 2>/dev/null && PUBLIC_ACCESS=true || PUBLIC_ACCESS=false

if [ "$PUBLIC_ACCESS" = true ]; then
  echo -e "${GREEN}✓ Public access enabled${NC}\n"
else
  echo -e "${YELLOW}⚠ Public access blocked by organisation policy${NC}\n"
fi

SERVICE_URL=$(gcloud run services describe $SERVICE_NAME \
  --region $REGION \
  --format 'value(status.url)')

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✓ Deployment successful!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${YELLOW}Service URL:${NC} ${GREEN}$SERVICE_URL${NC}"
echo ""
echo -e "${YELLOW}Validation tests:${NC}"
echo ""
echo "1. Health check:"
echo -e "   ${GREEN}curl $SERVICE_URL/health${NC}"
echo ""
echo "2. Ping (auth):"
echo -e "   ${GREEN}curl -u ${CW_ACCESS_KEY}:${CW_SECRET_KEY} $SERVICE_URL/api/v3/ping${NC}"
echo ""
echo "3. List assets:"
echo -e "   ${GREEN}curl -u ${CW_ACCESS_KEY}:${CW_SECRET_KEY} '$SERVICE_URL/api/v3/vulnerabilities/servers?per_page=5'${NC}"
echo ""
echo -e "${YELLOW}XSIAM configuration (Cyberwatch integration):${NC}"
echo "   Master scanner URL: $SERVICE_URL"
echo "   API Access key:     ${CW_ACCESS_KEY}"
echo "   API Secret key:     ${CW_SECRET_KEY}"
echo ""
echo -e "${YELLOW}Useful commands:${NC}"
echo "   View logs: gcloud run services logs read $SERVICE_NAME --region $REGION"
echo "   Delete:    gcloud run services delete $SERVICE_NAME --region $REGION"
echo ""
