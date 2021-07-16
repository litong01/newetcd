# pathecho
Echo the request path as the response body

This is a simple golang app which responses to a request url
as its response body. This was specifically made to accomendate
letencrypt dns challenge.


# To use pathecho in k8s env with tls on
Create a tls secret, then use the secret when configures the
pod:

```
##################################################################################################
# Pathecho service @ port 31056
##################################################################################################
apiVersion: v1
kind: Service
metadata:
  name: pathecho-31056
spec:
  ports:
  - port: 31056
    targetPort: 8080
    name: port31056
  selector:
    app: pathecho-31056
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pathecho-31056
  labels:
    app: pathecho-31056
spec:
  replicas: 1
  selector:
    matchLabels:
      app: pathecho-31056
  template:
    metadata:
      labels:
        app: pathecho-31056
    spec:
      serviceAccountName: pathecho-account
      volumes:
        - name: tlskeys
          secret:
            secretName: <secret name>
      containers:
      - name: pathecho
        image: docker.io/email4tong/pathecho:v1.0.0
        imagePullPolicy: Always
        ports:
        - containerPort: 8080
        env:
        - name: TLS_CERT
          value: "/etc/mytls/tls.crt"
        - name: TLS_KEY
          value: "/etc/mytls/tls.key"
        volumeMounts:
        - name: tlskeys
          mountPath: "/etc/mytls"
          readOnly: true
```