<?php

namespace Plugin\Wechatpay;

use App\Contracts\PaymentInterface;
use App\Exceptions\ApiException;
use App\Models\Order;
use App\Services\Plugin\AbstractPlugin;
use Plugin\Wechatpay\library\WeChatPayV3;

class Plugin extends AbstractPlugin implements PaymentInterface
{
    public function boot(): void
    {
        $this->filter('available_payment_methods', function (array $methods): array {
            if ($this->getConfig('enabled', true)) {
                $methods['Wechatpay'] = [
                    'name' => '微信支付',
                    'icon' => '💚',
                    'plugin_code' => $this->getPluginCode(),
                    'type' => 'plugin',
                ];
            }

            return $methods;
        });
    }

    public function form(): array
    {
        return [
            'app_id' => [
                'label' => 'APPID',
                'type' => 'string',
                'required' => true,
                'description' => '与商户号绑定的公众号、小程序或开放平台 APPID',
            ],
            'mch_id' => [
                'label' => '微信支付商户号',
                'type' => 'string',
                'required' => true,
                'description' => '普通商户 mchid',
            ],
            'merchant_serial_no' => [
                'label' => '商户 API 证书序列号',
                'type' => 'string',
                'required' => true,
                'description' => '商户 API 证书序列号，不是微信支付平台证书序列号',
            ],
            'merchant_private_key' => [
                'label' => '商户 API 证书私钥',
                'type' => 'text',
                'required' => true,
                'description' => 'apiclient_key.pem 内容；严禁提交到代码仓库或写入日志',
            ],
            'api_v3_key' => [
                'label' => 'APIv3 密钥',
                'type' => 'string',
                'required' => true,
                'description' => '商户平台设置的 32 字节 APIv3 密钥，用于解密回调',
            ],
            'wechatpay_public_key_id' => [
                'label' => '微信支付公钥 ID',
                'type' => 'string',
                'required' => true,
                'description' => 'PUB_KEY_ID_ 开头的微信支付公钥 ID',
            ],
            'wechatpay_public_key' => [
                'label' => '微信支付公钥',
                'type' => 'text',
                'required' => true,
                'description' => '商户平台下载的微信支付公钥，用于验证应答和回调签名',
            ],
            'product_name' => [
                'label' => '商品描述',
                'type' => 'string',
                'default' => '',
                'description' => '显示在微信支付账单中；留空时使用站点名称',
            ],
        ];
    }

    public function pay($order): array
    {
        $this->assertConfigured();

        $tradeNo = (string) $order['trade_no'];
        if (!preg_match('/^[0-9A-Za-z_\-|*]{6,32}$/', $tradeNo)) {
            throw new ApiException('XBoard 订单号不符合微信支付要求：需为 6-32 位数字、字母或 _-|*');
        }

        $description = trim((string) $this->getConfig('product_name', ''));
        if ($description === '') {
            $description = admin_setting('app_name', 'XBoard') . ' - 订阅';
        }

        $result = $this->client()->createNativeOrder([
            'appid' => (string) $this->getConfig('app_id'),
            'mchid' => (string) $this->getConfig('mch_id'),
            'description' => $this->truncateDescription($description),
            'out_trade_no' => $tradeNo,
            'notify_url' => (string) $order['notify_url'],
            'amount' => [
                'total' => (int) $order['total_amount'],
                'currency' => 'CNY',
            ],
        ]);

        if (!isset($result['code_url']) || !is_string($result['code_url'])) {
            throw new ApiException('微信支付下单成功但未返回 code_url');
        }

        return [
            'type' => 0,
            'data' => $result['code_url'],
        ];
    }

    public function notify($params): array|bool
    {
        try {
            $transaction = $this->client()->parsePaymentNotification(request());
        } catch (\Throwable) {
            return false;
        }

        if (($transaction['trade_state'] ?? null) !== 'SUCCESS') {
            return false;
        }

        if (($transaction['trade_type'] ?? null) !== 'NATIVE') {
            return false;
        }

        if (!hash_equals((string) $this->getConfig('app_id'), (string) ($transaction['appid'] ?? ''))) {
            return false;
        }

        if (!hash_equals((string) $this->getConfig('mch_id'), (string) ($transaction['mchid'] ?? ''))) {
            return false;
        }

        $tradeNo = (string) ($transaction['out_trade_no'] ?? '');
        $callbackNo = (string) ($transaction['transaction_id'] ?? '');
        if ($tradeNo === '' || $callbackNo === '') {
            return false;
        }

        $order = Order::where('trade_no', $tradeNo)->first();
        if (!$order) {
            return false;
        }

        $expectedAmount = (int) $order->total_amount + (int) ($order->handling_amount ?? 0);
        $paidAmount = $transaction['amount']['total'] ?? null;
        $currency = $transaction['amount']['currency'] ?? null;
        if (!is_int($paidAmount) || $paidAmount !== $expectedAmount || $currency !== 'CNY') {
            return false;
        }

        return [
            'trade_no' => $tradeNo,
            'callback_no' => $callbackNo,
            'custom_result' => '',
        ];
    }

    private function client(): WeChatPayV3
    {
        return new WeChatPayV3(
            mchId: (string) $this->getConfig('mch_id'),
            merchantSerialNo: (string) $this->getConfig('merchant_serial_no'),
            merchantPrivateKey: (string) $this->getConfig('merchant_private_key'),
            apiV3Key: (string) $this->getConfig('api_v3_key'),
            wechatPayPublicKeyId: (string) $this->getConfig('wechatpay_public_key_id'),
            wechatPayPublicKey: (string) $this->getConfig('wechatpay_public_key')
        );
    }

    private function assertConfigured(): void
    {
        $required = [
            'app_id',
            'mch_id',
            'merchant_serial_no',
            'merchant_private_key',
            'api_v3_key',
            'wechatpay_public_key_id',
            'wechatpay_public_key',
        ];

        foreach ($required as $key) {
            if (trim((string) $this->getConfig($key, '')) === '') {
                throw new ApiException("微信支付配置缺失：{$key}");
            }
        }

        if (strlen((string) $this->getConfig('api_v3_key')) !== 32) {
            throw new ApiException('微信支付 APIv3 密钥必须为 32 字节');
        }

        if (!str_starts_with((string) $this->getConfig('wechatpay_public_key_id'), 'PUB_KEY_ID_')) {
            throw new ApiException('微信支付公钥 ID 必须以 PUB_KEY_ID_ 开头');
        }
    }

    private function truncateDescription(string $description): string
    {
        if (function_exists('mb_strcut')) {
            return mb_strcut($description, 0, 127, 'UTF-8');
        }

        return substr($description, 0, 127);
    }
}
