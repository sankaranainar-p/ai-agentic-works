public class TestController {
    public ResponseEntity<?> login(LoginDto dto) {
        String url = "http://payment-gateway.internal/charge";
        log.info("Login attempt: " + dto.email + " password: " + dto.password);
        User user = repo.findByEmail(dto.email);
        return ResponseEntity.ok(user);
    }
}
