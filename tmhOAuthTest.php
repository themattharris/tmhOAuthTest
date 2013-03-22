<?php

define('TMH_INDENT', 25);
require 'vendor/autoload.php';

class mockTmhOAuth extends tmhOAuth {
  public function __construct($config=array()) {
    $config['block'] = true;
    parent::__construct($config);
  }
}

class tmhOAuthTest extends PHPUnit_Framework_TestCase {
  private function dtcExampleApp() {
    return new mockTmhOAuth(array(
      'consumer_key'    => 'xvz1evFS4wEEPTGEFPHBog',
      'consumer_secret' => 'kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw',
      'token'           => '370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb',
      'secret'          => 'LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE',
      'force_timestamp' => '1318622958',
      'force_nonce'     => 'kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg',
    ));
  }

  private function dtcExampleValidations($tmhOAuth) {
    $this->assertEquals(
      $tmhOAuth->request_settings['basestring'],
      'POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521'
    );
    $this->assertEquals(
      $tmhOAuth->request_settings['signing_key'],
      'kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE'
    );
    $this->assertEquals(
      $tmhOAuth->request_settings['headers']['Authorization'],
      'OAuth oauth_consumer_key="xvz1evFS4wEEPTGEFPHBog", oauth_nonce="kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg", oauth_signature="tnnArxj06cWHq44gCs1OSKk%2FjLY%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1318622958", oauth_token="370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb", oauth_version="1.0"'
    );
    $this->assertEquals($tmhOAuth->request_settings['postfields'], array(
      'include_entities' => 'true',
      'status' => 'Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21',
    ));
  }

  public function testBlockPreventsCurlRequests() {
    $tmhOAuth = new mockTmhOAuth();
    $tmhOAuth->unauthenticated_request(array(
      'method' => 'GET',
      'url' => 'http://localhost',
    ));
    $this->assertArrayNotHasKey(
      'info',
      $tmhOAuth->response
    );
    $this->assertArrayNotHasKey(
      'error',
      $tmhOAuth->response
    );
    $this->assertArrayNotHasKey(
      'errno',
      $tmhOAuth->response
    );
  }

  public function testUserAgentDefinable() {
    $ua = 'test user agent';
    $tmhOAuth = new mockTmhOAuth(array('user_agent' => $ua));

    $this->assertEquals($ua, $tmhOAuth->config['user_agent']);
  }

  public function testSymbolEncoding() {
    $tmhOAuth = new mockTmhOAuth();
    $tmhOAuth->request(
      'POST',
      $tmhOAuth->url('1/statuses/update'),
      array(
        'symbols' => '+%=^éçå ',
      )
    );
    $this->assertEquals($tmhOAuth->request_settings['postfields'], array(
      'symbols' => '%2B%25%3D%5E%C3%A9%C3%A7%C3%A5%20',
    ));
  }

  public function testOAuth1Signing() {
    $tmhOAuth = $this->dtcExampleApp();
    $tmhOAuth->request(
      'POST',
      $tmhOAuth->url('1/statuses/update'),
      array(
        'status' => 'Hello Ladies + Gentlemen, a signed OAuth request!',
        'include_entities' => 'true'
      )
    );
    $this->dtcExampleValidations($tmhOAuth);
  }

  public function testUserRequest() {
    $tmhOAuth = $this->dtcExampleApp();
    $tmhOAuth->user_request(array(
      'method' => 'POST',
      'url' => $tmhOAuth->url('1/statuses/update'),
      'params' => array(
        'status' => 'Hello Ladies + Gentlemen, a signed OAuth request!',
        'include_entities' => 'true'
      )
    ));
    $this->dtcExampleValidations($tmhOAuth);
  }

  public function testOAuth1AppOnlyRequest() {
    $tmhOAuth = $this->dtcExampleApp();
    $tmhOAuth->apponly_request(array(
      'method' => 'GET',
      'url' => $tmhOAuth->url('1/statuses/user_timeline'),
      'params' => array(
        'screen_name' => 'themattharris'
      )
    ));

    $this->assertArrayNotHasKey(
      'oauth_token',
      $tmhOAuth->request_settings['oauth1_params']
    );
    $this->assertEquals(
      $tmhOAuth->request_settings['basestring'],
      'GET&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fuser_timeline.json&oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_version%3D1.0%26screen_name%3Dthemattharris'
    );
    $this->assertEquals(
      $tmhOAuth->request_settings['signing_key'],
      'kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&'
    );
    $this->assertEquals(
      $tmhOAuth->request_settings['headers']['Authorization'],
      'OAuth oauth_consumer_key="xvz1evFS4wEEPTGEFPHBog", oauth_nonce="kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg", oauth_signature="PH2eOsQuERn64pHhmmPWZPkNLow%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1318622958", oauth_version="1.0"'
    );
  }

  public function testUnauthenticatedRequest() {
    $tmhOAuth = $this->dtcExampleApp();
    $tmhOAuth->unauthenticated_request(array(
      'method' => 'GET',
      'url' => $tmhOAuth->url('1/statuses/user_timeline'),
      'params' => array(
        'screen_name' => 'themattharris'
      ),
    ));

    $this->assertArrayNotHasKey(
      'oauth1_params',
      $tmhOAuth->request_settings
    );
    $this->assertArrayNotHasKey(
      'Authorization',
      $tmhOAuth->request_settings['headers']
    );
  }

  public function testOAuth2AppOnlyRequest() {

  }

  public function testSettingUserTokenAndSecret() {
    $config = array(
      'consumer_key' => 'CONSUMER_KEY',
      'consumer_secret' => 'CONSUMER_SECRET',
      'user_token' => 'OAUTH_TOKEN',
      'user_secret' => 'OAUTH_SECRET',
    );
    $tmhOAuth = new mockTmhOAuth($config);
    $tmhOAuth->user_request(array(
      'url' => 'http://localhost'
    ));
    $this->assertArrayHasKey(
      'oauth1_params',
      $tmhOAuth->request_settings
    );
    $this->assertEquals(
      $config['user_token'],
      $tmhOAuth->request_settings['oauth1_params']['oauth_token']
    );
    $this->assertEquals(
      $tmhOAuth->request_settings['signing_key'],
      "${config['consumer_secret']}&${config['user_secret']}"
    );
  }

  public function testSettingOAuthTokenAndSecret() {
    $config = array(
      'consumer_key' => 'CONSUMER_KEY',
      'consumer_secret' => 'CONSUMER_SECRET',
      'token' => 'OAUTH_TOKEN',
      'secret' => 'OAUTH_SECRET',
    );
    $tmhOAuth = new mockTmhOAuth($config);
    $tmhOAuth->user_request(array(
      'url' => 'http://localhost'
    ));
    $this->assertArrayHasKey(
      'oauth1_params',
      $tmhOAuth->request_settings
    );
    $this->assertEquals(
      $config['token'],
      $tmhOAuth->request_settings['oauth1_params']['oauth_token']
    );
    $this->assertEquals(
      $tmhOAuth->request_settings['signing_key'],
      "${config['consumer_secret']}&${config['secret']}"
    );
  }

  public function testReconfigure() {
    $config = array(
      'consumer_key' => 'CONSUMER_KEY',
      'consumer_secret' => 'CONSUMER_SECRET',
      'token' => 'OAUTH_TOKEN',
      'secret' => 'OAUTH_SECRET',
    );
    $config2 = array(
      'consumer_key' => 'SOME_KEY',
      'secret' => 'SOME_SECRET'
    );

    $tmhOAuth = new mockTmhOAuth($config);
    foreach ($config as $k => $v) {
      $this->assertEquals(
        $v,
        $tmhOAuth->config["${k}"]
      );
    }
    $tmhOAuth->reconfigure($config2);
    foreach ($config2 as $k => $v) {
      $this->assertEquals(
        $v,
        $tmhOAuth->config["${k}"]
      );
    }

    $this->assertEquals(
      '',
      $tmhOAuth->config['token']
    );
    $this->assertEquals(
      '',
      $tmhOAuth->config['consumer_secret']
    );
  }
}