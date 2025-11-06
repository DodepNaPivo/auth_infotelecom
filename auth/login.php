<?php
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

require_once __DIR__ . '/../config/database.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Метод не разрешен']);
    exit;
}

try {
    $pdo = getDBConnection();
    
    $data = json_decode(file_get_contents('php://input'), true);
    
    if (empty($data)) {
        $data = $_POST;
    }
    
    if (empty($data['email']) || empty($data['password'])) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Введите email и пароль']);
        exit;
    }
    
    $stmt = $pdo->prepare("SELECT id, name, email, phone, password, role, registered_at FROM users WHERE email = :email");
    $stmt->execute([':email' => $data['email']]);
    $user = $stmt->fetch();
    
    if (!$user) {
        http_response_code(401);
        echo json_encode(['success' => false, 'error' => 'Неверный email или пароль']);
        exit;
    }
    
    $passwordValid = false;
    
    if ($user['password'] === $data['password']) {
        $passwordValid = true;
    }
    else if (password_verify($data['password'], $user['password'])) {
        $passwordValid = true;
    }
    
    if (!$passwordValid) {
        http_response_code(401);
        echo json_encode(['success' => false, 'error' => 'Неверный email или пароль']);
        exit;
    }
    
    unset($user['password']);
    
    echo json_encode([
        'success' => true,
        'user' => $user,
        'message' => 'Вход выполнен успешно'
    ], JSON_UNESCAPED_UNICODE);
    
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'Ошибка входа: ' . $e->getMessage()
    ], JSON_UNESCAPED_UNICODE);
}
?>
