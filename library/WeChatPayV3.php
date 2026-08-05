<?php

namespace Plugin\Wechatpay\library;

use App\Exceptions\ApiException;
use Illuminate\Http\Client\Response;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use JsonException;
use RuntimeException;

class WeChatPayV3
{
    private const HOST = 'https://api.mch.weixin.qq.com';
    private const NATIVE_PATH = '/v3/pay/transactions/native';

    public function __construct(
        private readonly string $mchId,
        private readonly string $merchantSerialNo,
        private readonly string $merchantPrivateKey,
        private readonly string $apiV3Key,
        private readonly string $wechatPayPublicKeyId,
        private readonly string $wechatPayPublicKey
    ) {
    }

    public function createNativeOrder(array $payload): array
    {
        $body = json_encode(
            $payload,
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
        );
        $authorization = $this->buildAuthorization('POST', self::NATIVE_PATH, $body);

        $response = Http::connectTimeout(5)
            ->timeout(10)
            ->withHeaders([
                'Accept' => 'application/json',
                'Authorization' => $authorization,
                'Wechatpay-Serial' => $this->wechatPayPublicKeyId,
            ])
            ->withBody($body, 'application/json')
            ->post(self::HOST . self::NATIVE_PATH);

        $this->verifyResponse($response);

        try {
            $data = json_decode($response->body(), true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new ApiException('微信支付返回了无法解析的响应');
        }

        if (!$response->successful()) {
            $code = is_array($data) ? (string) ($data['code'] ?? 'UNKNOWN') : 'UNKNOWN';
            $message = is_array($data) ? (string) ($data['message'] ?? '请求失败') : '请求失败';
            throw new ApiException("微信支付下单失败：{$code} {$message}");
        }

        if (!is_array($data)) {
            throw new ApiException('微信支付返回格式错误');
        }

        return $data;
    }

    public function parsePaymentNotification(Request $request): array
    {
        $body = $request->getContent();
        $timestamp = (string) $request->header('Wechatpay-Timestamp', '');
        $nonce = (string) $request->header('Wechatpay-Nonce', '');
        $signature = (string) $request->header('Wechatpay-Signature', '');
        $serial = (string) $request->header('Wechatpay-Serial', '');

        if ($body === '' || $timestamp === '' || $nonce === '' || $signature === '' || $serial === '') {
            throw new RuntimeException('微信支付回调缺少必要签名信息');
        }

        if (!ctype_digit($timestamp) || abs(time() - (int) $timestamp) > 300) {
            throw new RuntimeException('微信支付回调时间戳无效或已过期');
        }

        if (!hash_equals($this->wechatPayPublicKeyId, $serial)) {
            throw new RuntimeException('微信支付回调公钥 ID 不匹配');
        }

        if (!$this->verifySignature($timestamp . "\n" . $nonce . "\n" . $body . "\n", $signature)) {
            throw new RuntimeException('微信支付回调验签失败');
        }

        $notification = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($notification)
            || ($notification['event_type'] ?? null) !== 'TRANSACTION.SUCCESS'
            || ($notification['resource_type'] ?? null) !== 'encrypt-resource'
            || !is_array($notification['resource'] ?? null)) {
            throw new RuntimeException('微信支付回调类型不受支持');
        }

        $resource = $notification['resource'];
        if (($resource['algorithm'] ?? null) !== 'AEAD_AES_256_GCM'
            || ($resource['original_type'] ?? null) !== 'transaction') {
            throw new RuntimeException('微信支付回调加密算法或资源类型无效');
        }

        $plaintext = $this->decryptResource(
            (string) ($resource['associated_data'] ?? ''),
            (string) ($resource['nonce'] ?? ''),
            (string) ($resource['ciphertext'] ?? '')
        );

        $transaction = json_decode($plaintext, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($transaction)) {
            throw new RuntimeException('微信支付回调交易数据格式错误');
        }

        return $transaction;
    }

    private function buildAuthorization(string $method, string $path, string $body): string
    {
        $timestamp = (string) time();
        $nonce = bin2hex(random_bytes(16));
        $message = $method . "\n" . $path . "\n" . $timestamp . "\n" . $nonce . "\n" . $body . "\n";
        $signature = $this->sign($message);

        return sprintf(
            'WECHATPAY2-SHA256-RSA2048 mchid="%s",nonce_str="%s",signature="%s",timestamp="%s",serial_no="%s"',
            $this->mchId,
            $nonce,
            $signature,
            $timestamp,
            $this->merchantSerialNo
        );
    }

    private function verifyResponse(Response $response): void
    {
        $timestamp = (string) $response->header('Wechatpay-Timestamp');
        $nonce = (string) $response->header('Wechatpay-Nonce');
        $signature = (string) $response->header('Wechatpay-Signature');
        $serial = (string) $response->header('Wechatpay-Serial');

        if ($timestamp === '' || $nonce === '' || $signature === '' || $serial === '') {
            throw new ApiException('微信支付响应缺少签名头，已拒绝处理');
        }

        if (!ctype_digit($timestamp) || abs(time() - (int) $timestamp) > 300) {
            throw new ApiException('微信支付响应时间戳无效或已过期');
        }

        if (!hash_equals($this->wechatPayPublicKeyId, $serial)) {
            throw new ApiException('微信支付响应公钥 ID 不匹配');
        }

        $message = $timestamp . "\n" . $nonce . "\n" . $response->body() . "\n";
        if (!$this->verifySignature($message, $signature)) {
            throw new ApiException('微信支付响应验签失败');
        }
    }

    private function sign(string $message): string
    {
        $privateKey = openssl_pkey_get_private($this->normalizePrivateKey($this->merchantPrivateKey));
        if ($privateKey === false) {
            throw new RuntimeException('微信支付商户 API 私钥不可用');
        }

        $signature = '';
        if (!openssl_sign($message, $signature, $privateKey, OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('微信支付请求签名失败');
        }

        return base64_encode($signature);
    }

    private function verifySignature(string $message, string $signature): bool
    {
        if (str_starts_with($signature, 'WECHATPAY/SIGNTEST/')) {
            return false;
        }

        $signatureBytes = base64_decode($signature, true);
        if ($signatureBytes === false) {
            return false;
        }

        $publicKey = openssl_pkey_get_public($this->normalizePublicKey($this->wechatPayPublicKey));
        if ($publicKey === false) {
            throw new RuntimeException('微信支付公钥不可用');
        }

        return openssl_verify($message, $signatureBytes, $publicKey, OPENSSL_ALGO_SHA256) === 1;
    }

    private function decryptResource(string $associatedData, string $nonce, string $ciphertext): string
    {
        if (strlen($this->apiV3Key) !== 32) {
            throw new RuntimeException('微信支付 APIv3 密钥必须为 32 字节');
        }

        $decoded = base64_decode($ciphertext, true);
        if ($decoded === false || strlen($decoded) <= 16) {
            throw new RuntimeException('微信支付回调密文无效');
        }

        $encrypted = substr($decoded, 0, -16);
        $tag = substr($decoded, -16);
        $plaintext = openssl_decrypt(
            $encrypted,
            'aes-256-gcm',
            $this->apiV3Key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $associatedData
        );

        if ($plaintext === false) {
            throw new RuntimeException('微信支付回调解密失败');
        }

        return $plaintext;
    }

    private function normalizePrivateKey(string $key): string
    {
        $key = trim(str_replace(["\r\n", "\r"], "\n", $key));
        if (str_contains($key, 'BEGIN PRIVATE KEY') || str_contains($key, 'BEGIN RSA PRIVATE KEY')) {
            return $key;
        }

        $body = preg_replace('/\s+/', '', $key);
        return "-----BEGIN PRIVATE KEY-----\n"
            . chunk_split((string) $body, 64, "\n")
            . "-----END PRIVATE KEY-----";
    }

    private function normalizePublicKey(string $key): string
    {
        $key = trim(str_replace(["\r\n", "\r"], "\n", $key));
        if (str_contains($key, 'BEGIN PUBLIC KEY')) {
            return $key;
        }

        $body = preg_replace('/\s+/', '', $key);
        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split((string) $body, 64, "\n")
            . "-----END PUBLIC KEY-----";
    }
}
