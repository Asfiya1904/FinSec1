curl -X POST http://localhost:5000/detect \
  -H "Authorization: Bearer supersecret" \
  -H "Content-Type: application/json" \
  -d '{"TransactionID": 1001, "Amount": 4999.99, "AccountAgeDays": 87, "FailedAttempts": 3, "TimeSinceLastLogin": 0.5}'
