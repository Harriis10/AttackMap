// Static reference input only. AttackMap never executes these calls.
fetch("http://prod-api.example/Api/Users/42");
fetch("http://dev-api.example/Api/Users/42");
fetch("http://unknown-api.example/Api/Users/42");
fetch("http://auth-api/Api/Users/42");
fetch("http://prod-api.example/api/users/42");
fetch("grpc://prod-api.example/Api/Users/42");
fetch("http://multi.example/Api/Users/42");
fetch("http://auth-api.prod.svc.cluster.local/Api/Users/42");
fetch("http://cross.example/Api/Users/42");
