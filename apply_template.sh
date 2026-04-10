#!/bin/bash
# Run this ONCE before starting Logstash / before any logs are indexed.
# It registers the index template so `location` is a geo_point from day one.

ES="http://localhost:9200"

echo "[1/3] Waiting for Elasticsearch..."
until curl -s "$ES/_cluster/health" | grep -q '"status"'; do sleep 2; done
echo "      Elasticsearch is up."

echo "[2/3] Applying index template auth-logs-template..."
curl -s -X PUT "$ES/_index_template/auth-logs-template" \
  -H "Content-Type: application/json" \
  -d @es_index_template.json | python3 -m json.tool

echo ""
echo "[3/3] Done. You can now start Logstash."
echo ""
echo "Verify with:"
echo "  curl $ES/_index_template/auth-logs-template"