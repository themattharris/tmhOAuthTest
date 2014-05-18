<?php

define('TMH_INDENT', 25);
require 'vendor/autoload.php';

class mockTmhOAuth extends tmhOAuth {
  public function __construct($config=array()) {
    $config['block'] = true;
    parent::__construct($config);
  }
}

echo 'Testing tmhOAuth ' . mockTmhOAuth::VERSION . PHP_EOL;

class tmhOAuthTest extends PHPUnit_Framework_TestCase {
  private function dtcAppOnlyExampleApp() {
    return new mockTmhOAuth(array(
      'bearer' => 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%2FAAAAAAAAAAAAAAAAAAAA%3DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    ));
  }

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

  private function mediaOrCurlFile() {
    if (class_exists('CurlFile', false))
      return new CurlFile(__FILE__);

    return "@".__FILE__.";type=image/jpeg;filename=picture.jpg";
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
    $this->assertEquals($tmhOAuth->request_settings['prepared_params'], array(
      'include_entities' => 'true',
      'status' => 'Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21',
    ));
    $this->assertEquals($tmhOAuth->request_settings['postfields'],
      "include_entities=true&status=Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21"
    );
  }

  public function testBlockPreventsCurlRequests() {
    $tmhOAuth = new mockTmhOAuth();
    $tmhOAuth->unauthenticated_request(array(
      'url' => 'http://localhost.local',
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

  // UserAgent
  public function testUserAgentDefinable() {
    $ua = 'test user agent';
    $tmhOAuth = new mockTmhOAuth(array('user_agent' => $ua));

    $this->assertEquals($ua, $tmhOAuth->config['user_agent']);
  }

  public function testSSLSignInUserAgentWithVerifyhost() {
    $tmhOAuth = new mockTmhOAuth(array('curl_ssl_verifyhost' => false));
    $this->assertContains('-SSL', $tmhOAuth->config['user_agent']);
    $this->assertNotContains('+SSL', $tmhOAuth->config['user_agent']);
  }

  public function testSSLSignInUserAgentWithVerifyPeer() {
    $tmhOAuth = new mockTmhOAuth(array('curl_ssl_verifypeer' => false));
    $this->assertContains('-SSL', $tmhOAuth->config['user_agent']);
    $this->assertNotContains('+SSL', $tmhOAuth->config['user_agent']);
  }

  public function testSSLSignInUserAgent() {
    $tmhOAuth = new mockTmhOAuth();
    $this->assertContains('+SSL', $tmhOAuth->config['user_agent']);
    $this->assertNotContains('-SSL', $tmhOAuth->config['user_agent']);
  }

  // URLs
  public function testFunctionUrl() {
    $tmhOAuth = new mockTmhOAuth(array('host' => 'localhost.local'));
    $this->assertEquals(
      $tmhOAuth->url('/path/to/something'),
      'https://localhost.local/path/to/something.json'
    );
  }

  public function testFunctionUrlWithCustomExtension() {
    $tmhOAuth = new mockTmhOAuth(array('host' => 'localhost.local'));
    $this->assertEquals(
      $tmhOAuth->url('/path/to/something','xml'),
      'https://localhost.local/path/to/something.xml'
    );
  }

  public function testFunctionUrlWithNoExtension() {
    $tmhOAuth = new mockTmhOAuth(array('host' => 'localhost.local'));
    $this->assertEquals(
      $tmhOAuth->url('/path/to/something',''),
      'https://localhost.local/path/to/something'
    );
  }

  public function testFunctionUrlWithDoubleSlashes() {
    $tmhOAuth = new mockTmhOAuth(array('host' => 'localhost.local'));
    $this->assertEquals(
      $tmhOAuth->url('/path/to//something'),
      'https://localhost.local/path/to/something.json'
    );
  }

  public function testFunctionUrlWithProtocol() {
    $tmhOAuth = new mockTmhOAuth(array('host' => 'localhost.local'));
    $this->assertEquals(
      $tmhOAuth->url('https://localhost.mine/path/to/something'),
      'https://localhost.mine/path/to/something'
    );
  }

  public function testFunctionUrlWithExtension() {
    $tmhOAuth = new mockTmhOAuth(array('host' => 'localhost.local'));
    $this->assertEquals(
      $tmhOAuth->url('/path/to/something.json'),
      'https://localhost.local/path/to/something.json'
    );
  }

  public function testFunctionUrlWithSlashProtocol() {
    $tmhOAuth = new mockTmhOAuth(array('host' => 'localhost.local'));
    $this->assertEquals(
      $tmhOAuth->url('//localhost.mine/path/to/something.json'),
      '//localhost.mine/path/to/something.json'
    );
  }

  public function testSymbolEncoding() {
    $tmhOAuth = new mockTmhOAuth();

    $syms = '';
    for ($i=0; $i < 255; $i++) {
      $syms .= chr($i);
    }
    $tmhOAuth->unauthenticated_request(array(
      'method' => 'POST',
      'url' => 'http://localhost',
      'params' => array(
        'symbols' => $syms,
      )
    ));

    $this->assertEquals($tmhOAuth->request_settings['prepared_params'], array(
      'symbols' => '%00%01%02%03%04%05%06%07%08%09%0A%0B%0C%0D%0E%0F%10%11%12%13%14%15%16%17%18%19%1A%1B%1C%1D%1E%1F'.
                   '%20%21%22%23%24%25%26%27%28%29%2A%2B%2C-.%2F0123456789%3A%3B%3C%3D%3E%3F%40ABCDEFGHIJKLMNOPQRSTUVWXYZ'.
                   '%5B%5C%5D%5E_%60abcdefghijklmnopqrstuvwxyz%7B%7C%7D~%7F%80%81%82%83%84%85%86%87%88%89%8A%8B%8C%8D%8E%8F'.
                   '%90%91%92%93%94%95%96%97%98%99%9A%9B%9C%9D%9E%9F%A0%A1%A2%A3%A4%A5%A6%A7%A8%A9%AA%AB%AC%AD%AE%AF'.
                   '%B0%B1%B2%B3%B4%B5%B6%B7%B8%B9%BA%BB%BC%BD%BE%BF%C0%C1%C2%C3%C4%C5%C6%C7%C8%C9%CA%CB%CC%CD%CE%CF'.
                   '%D0%D1%D2%D3%D4%D5%D6%D7%D8%D9%DA%DB%DC%DD%DE%DF%E0%E1%E2%E3%E4%E5%E6%E7%E8%E9%EA%EB%EC%ED%EE%EF'.
                   '%F0%F1%F2%F3%F4%F5%F6%F7%F8%F9%FA%FB%FC%FD%FE',
    ));

    $this->assertEquals($tmhOAuth->request_settings['postfields'],
      'symbols=%00%01%02%03%04%05%06%07%08%09%0A%0B%0C%0D%0E%0F%10%11%12%13%14%15%16%17%18%19%1A%1B%1C%1D%1E%1F'.
               '%20%21%22%23%24%25%26%27%28%29%2A%2B%2C-.%2F0123456789%3A%3B%3C%3D%3E%3F%40ABCDEFGHIJKLMNOPQRSTUVWXYZ'.
               '%5B%5C%5D%5E_%60abcdefghijklmnopqrstuvwxyz%7B%7C%7D~%7F%80%81%82%83%84%85%86%87%88%89%8A%8B%8C%8D%8E%8F'.
               '%90%91%92%93%94%95%96%97%98%99%9A%9B%9C%9D%9E%9F%A0%A1%A2%A3%A4%A5%A6%A7%A8%A9%AA%AB%AC%AD%AE%AF'.
               '%B0%B1%B2%B3%B4%B5%B6%B7%B8%B9%BA%BB%BC%BD%BE%BF%C0%C1%C2%C3%C4%C5%C6%C7%C8%C9%CA%CB%CC%CD%CE%CF'.
               '%D0%D1%D2%D3%D4%D5%D6%D7%D8%D9%DA%DB%DC%DD%DE%DF%E0%E1%E2%E3%E4%E5%E6%E7%E8%E9%EA%EB%EC%ED%EE%EF'.
               '%F0%F1%F2%F3%F4%F5%F6%F7%F8%F9%FA%FB%FC%FD%FE'
    );
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

  public function testUserPostRequest() {
    $tmhOAuth = $this->dtcExampleApp();
    $tmhOAuth->user_request(array(
      'method' => 'POST',
      'url' => $tmhOAuth->url('1/statuses/update'),
      'params' => array(
        'status' => 'Hello Ladies + Gentlemen, a signed OAuth request!',
        'include_entities' => 'true'
      )
    ));

    $this->assertEquals(
      $tmhOAuth->request_settings['url'],
      'https://api.twitter.com/1/statuses/update.json'
    );
    $this->assertEquals(
      $tmhOAuth->request_settings['prepared_params'],
      array(
        'include_entities' => 'true',
        'status' => 'Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21',
    ));
    $this->assertEquals(
      $tmhOAuth->request_settings['postfields'],
      "include_entities=true&status=Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21"
    );
    $this->assertEquals(
      $tmhOAuth->request_settings['basestring'],
      'POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521'
    );
  }

  public function testUserGetRequest() {
    $tmhOAuth = $this->dtcExampleApp();
    $tmhOAuth->user_request(array(
      'method' => 'GET',
      'url' => $tmhOAuth->url('1.1/users/lookup'),
      'params' => array(
        'user_id' => array(
          777925,
        ),
        'screen_name' => array(
          'tmhoauth',
        ),
        'map' => 1
      )
    ));

    $this->assertEquals(
      $tmhOAuth->request_settings['url'],
      'https://api.twitter.com/1.1/users/lookup.json?map=1&screen_name=tmhoauth&user_id=777925'
    );
    $this->assertEquals(
      $tmhOAuth->request_settings['prepared_params'],
      array(
        'map' => '1',
        'screen_name' => 'tmhoauth',
        'user_id' => '777925'
    ));
    $this->assertEquals(
      $tmhOAuth->request_settings['querystring'],
      "map=1&screen_name=tmhoauth&user_id=777925"
    );
    $this->assertEquals(
      $tmhOAuth->request_settings['basestring'],
      'GET&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fusers%2Flookup.json&map%3D1%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26screen_name%3Dtmhoauth%26user_id%3D777925'
    );
  }

  public function testUserMultipartRequest() {
    $tmhOAuth = $this->dtcExampleApp();
    $tmhOAuth->user_request(array(
      'method' => 'POST',
      'url' => $tmhOAuth->url('1.1/statuses/update_with_media'),
      'params' => array(
        'media[]'  => $this->mediaOrCurlFile(),
        'status'   => 'a photo',
      ),
      'multipart' => true,
    ));

    $this->assertEquals(
      $tmhOAuth->request_settings['url'],
      'https://api.twitter.com/1.1/statuses/update_with_media.json'
    );
    $this->assertEquals(
      $tmhOAuth->request_settings['prepared_params'],
      array(
        'media[]'  => $this->mediaOrCurlFile(),
        'status'   => 'a photo',
    ));
    $this->assertEquals(
      $tmhOAuth->request_settings['postfields'],
      array(
        'media[]'  => $this->mediaOrCurlFile(),
        'status'   => 'a photo',
    ));
    $this->assertEquals(
      $tmhOAuth->request_settings['basestring'],
      'POST&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fstatuses%2Fupdate_with_media.json&oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0'
    );
  }

  public function testMultipartEscaping() {
    $tmhOAuth = $this->dtcExampleApp();
    $tmhOAuth->user_request(array(
      'method' => 'POST',
      'url' => $tmhOAuth->url('1.1/statuses/update_with_media'),
      'params' => array(
        'media[]'  => $this->mediaOrCurlFile(),
        'status'   => "@tmhOAuth posted a picture",
      ),
      'multipart' => true,
    ));

    $this->assertEquals(
      $tmhOAuth->request_settings['prepared_params'],
      array(
        'media[]'  => $this->mediaOrCurlFile(),
        'status'   => " @tmhOAuth posted a picture",
    ));
    $this->assertEquals(
      $tmhOAuth->request_settings['postfields'],
      array(
        'media[]'  => $this->mediaOrCurlFile(),
        'status'   => " @tmhOAuth posted a picture",
    ));
    $this->assertEquals(
      $tmhOAuth->request_settings['basestring'],
      'POST&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fstatuses%2Fupdate_with_media.json&oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0'
    );
  }

  public function testMultipartEscapingDoesntDoAnythingOnFormEncoded() {
    $tmhOAuth = $this->dtcExampleApp();
    $tmhOAuth->user_request(array(
      'method' => 'POST',
      'url' => $tmhOAuth->url('1/statuses/update'),
      'params' => array(
        'status' => '@tmhOAuth, see my signed OAuth request!',
        'include_entities' => 'true'
      )
    ));

    $this->assertEquals(
      $tmhOAuth->request_settings['prepared_params'],
      array(
        'status'   => "%40tmhOAuth%2C%20see%20my%20signed%20OAuth%20request%21",
        'include_entities' => 'true',
    ));
    $this->assertEquals(
      $tmhOAuth->request_settings['postfields'],
      "include_entities=true&status=%40tmhOAuth%2C%20see%20my%20signed%20OAuth%20request%21"
    );
  }

  public function testOAuth1AppOnlyRequest() {
    $tmhOAuth = $this->dtcExampleApp();
    $tmhOAuth->apponly_request(array(
      'without_bearer' => true,
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
    $this->assertEquals(
      $tmhOAuth->request_settings['url'],
      'https://api.twitter.com/1/statuses/user_timeline.json?screen_name=themattharris'
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

  // AppOnly
  public function testOAuth2AppOnlyRequest() {
    $tmhOAuth = $this->dtcAppOnlyExampleApp();
    $tmhOAuth->apponly_request(array(
      'method' => 'GET',
      'url' => $tmhOAuth->url('1.1/statuses/user_timeline'),
      'params' => array(
        'count' => 100,
        'screen_name' => 'twitterapi'
      )
    ));

    $this->assertEquals(
      'https://api.twitter.com/1.1/statuses/user_timeline.json?count=100&screen_name=twitterapi',
      $tmhOAuth->request_settings['url']
    );
    $this->assertEquals(
      'count=100&screen_name=twitterapi',
      $tmhOAuth->request_settings['querystring']
    );
    $this->assertArrayNotHasKey(
      'oauth1_params',
      $tmhOAuth->request_settings
    );
    $this->assertArrayNotHasKey(
      'postfields',
      $tmhOAuth->request_settings
    );
    $this->assertArrayHasKey(
      'Authorization',
      $tmhOAuth->request_settings['headers']
    );
    $this->assertEquals(
      'Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%2FAAAAAAAAAAAAAAAAAAAA%3DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      $tmhOAuth->request_settings['headers']['Authorization']
    );
  }

  public function testOAuth2BearTokenCredentials() {
    $tmhOAuth = new mockTmhOAuth(array(
      'consumer_key'    => 'xvz1evFS4wEEPTGEFPHBog',
      'consumer_secret' => 'L8qq9PZyRg6ieKGEKhZolGC0vJWLw8iEJ88DRdyOg',
    ));
    $this->assertEquals(
      'eHZ6MWV2RlM0d0VFUFRHRUZQSEJvZzpMOHFxOVBaeVJnNmllS0dFS2hab2xHQzB2SldMdzhpRUo4OERSZHlPZw==',
      $tmhOAuth->bearer_token_credentials()
    );
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
      'url' => 'http://localhost.local'
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
      'url' => 'http://localhost.local'
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

  public function testRequestDefaults() {
    $tmhOAuth = new mockTmhOAuth();
    $tmhOAuth->unauthenticated_request(array(
      'url' => 'http://localhost.local',
    ));
    $this->assertEquals(
      'GET',
      $tmhOAuth->request_settings['method']
    );
  }
}
