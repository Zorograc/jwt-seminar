<?php
require 'vendor/autoload.php';
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\JWK;

$privateKey = file_get_contents('/keys/private.pem');
$publicKey = file_get_contents('/keys/public.pem');

$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

function getVerifyKey($token, $publicKey) {
    $parts = explode('.', $token);
    $header = json_decode(base64_decode(str_pad(strtr($parts[0], '-_', '+/'), strlen($parts[0]) % 4, '=')), true);
    
    if (isset($header['kid'])) {
        $keyPath = '/keys/' . $header['kid'];
        $keyContent = file_get_contents($keyPath);
        return new \Firebase\JWT\Key($keyContent, 'HS256');
    }
    return new \Firebase\JWT\Key($publicKey, 'RS256');
}

if ($path === '/login' && $method === 'POST') {
    $payload = ['user' => 'testuser', 'role' => 'user', 'exp' => time() + 3600];
    $token = JWT::encode($payload, $privateKey, 'RS256');
    echo json_encode(['token' => $token]);

} elseif ($path === '/verify' && $method === 'POST') {
    $body = json_decode(file_get_contents('php://input'), true);
    try {
        $key = getVerifyKey($body['token'], $publicKey);
        $decoded = JWT::decode($body['token'], $key);
        echo json_encode(['valid' => true, 'payload' => $decoded]);
    } catch (Exception $e) {
        echo json_encode(['valid' => false, 'error' => $e->getMessage()]);
    }

} elseif ($path === '/admin' && $method === 'GET') {
    $token = str_replace('Bearer ', '', $_SERVER['HTTP_AUTHORIZATION'] ?? '');
    try {
        $key = getVerifyKey($token, $publicKey);
        $decoded = JWT::decode($token, $key);
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