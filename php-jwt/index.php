<?php
require 'vendor/autoload.php';
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$secret = 'supersecretkey123';
$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

if ($path === '/login' && $method === 'POST') {
    $payload = ['user' => 'testuser', 'role' => 'user', 'exp' => time() + 3600];
    $token = JWT::encode($payload, $secret, 'HS256');
    echo json_encode(['token' => $token]);

} elseif ($path === '/verify' && $method === 'POST') {
    $body = json_decode(file_get_contents('php://input'), true);
    try {
        $decoded = JWT::decode($body['token'], new Key($secret, 'HS256'));
        echo json_encode(['valid' => true, 'payload' => $decoded]);
    } catch (Exception $e) {
        echo json_encode(['valid' => false, 'error' => $e->getMessage()]);
    }

} elseif ($path === '/admin' && $method === 'GET') {
    $token = str_replace('Bearer ', '', $_SERVER['HTTP_AUTHORIZATION'] ?? '');
    try {
        $decoded = JWT::decode($token, new Key($secret, 'HS256'));
        if ($decoded->role === 'admin') {
            echo json_encode(['message' => 'Dobrodošel, admin!']);
        } else {
            http_response_code(403);
            echo json_encode(['error' => 'Nisi admin']);
        }
    } catch (Exception $e) {
        http_response_code(401);
        echo json_encode(['error' => $e->getMessage()]);
    }
}