// Static source only; never executed.
fetch("http://prod-api.example/Items/42");
fetch("https://dev-api.example:9443/Items/42");
fetch("http://unknown.example/Items/42");
fetch("http://auth-api/Items/42");
fetch("grpc://prod-api.example/Items/42");
fetch("http://wrong-port.example/Items/42");
fetch("http://auth-api.prod.svc.cluster.local/Items/42");
fetch("https://dev-api.example/Items/42");
fetch("http://prod-api.example/items/42");
fetch("https://telemetry.external.example/Telemetry");
