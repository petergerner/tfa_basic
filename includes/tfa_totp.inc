<?php

/**
 * @file classes for tfa_totp
 */

/**
 * Class TfaTotp
 */
class TfaTotp extends TfaBasePlugin implements TfaValidationPluginInterface {

  /**
   * @var PHPGangsta_GoogleAuthenticator
   */
  protected $ga;

  /**
   * @var int
   */
  protected $timeSkew;

  /**
   * @var bool
   */
  protected $alreadyAccepted;

  /**
   * @copydoc TfaBasePlugin::__construct()
   */
  public function __construct(array $context) {
    parent::__construct($context);
    $this->ga = new PHPGangsta_GoogleAuthenticator();
    // Allow codes within tolerance range of 3 * 30 second units.
    $this->timeSkew = variable_get('tfa_basic_time_skew', 3);
    // Recommended: set variable tfa_totp_secret_key in settings.php.
    $this->encryptionKey = variable_get('tfa_basic_secret_key', drupal_get_private_key());
    $this->alreadyAccepted = FALSE;
  }

  /**
   * @copydoc TfaBasePlugin::ready()
   */
  public function ready() {
    return ($this->getSeed() !== FALSE);
  }

  /**
   * @copydoc TfaValidationPluginInterface::getForm()
   */
  public function getForm(array $form, array &$form_state) {
    $form['code'] = array(
      '#type' => 'textfield',
      '#title' => t('Application verification code'),
      '#description' => t('Verification code is application generated and !length digits long.', array('!length' => $this->codeLength)),
      '#required' => TRUE,
      '#attributes' => array('autocomplete' => 'off'),
    );
    if (module_exists('elements')) {
      $form['code']['#type'] = 'numberfield';
    }
    $form['actions']['#type'] = 'actions';
    $form['actions']['login'] = array(
      '#type' => 'submit',
      '#value' => t('Verify'),
    );

    return $form;
  }

  /**
   * @copydoc TfaValidationPluginInterface::validateForm()
   */
  public function validateForm(array $form, array &$form_state) {
    if (!$this->validate($form_state['values']['code'])) {
      $this->errorMessages['code'] = t('Érvénytelen kód, próbáld meg újra.');
      if ($this->alreadyAccepted) {
        $this->errorMessages['code'] = t('Érvénytelen, már használt kód. Várd meg az appban, hogy újabb kódot generáljon, és probáld azzal újra!.');
      }
      return FALSE;
    }
    else {
      // Store accepted code to prevent replay attacks.
      $this->storeAcceptedCode($form_state['values']['code']);
      return TRUE;
    }
  }

  /**
   * @copydoc TfaBasePlugin::validate()
   */
  protected function validate($code) {
    // Strip whitespace.
    $code = preg_replace('/\s+/', '', $code);
    if ($this->alreadyAcceptedCode($code)) {
      $this->isValid = FALSE;
    }
    else {
      // Get OTP seed.
      $seed = $this->getSeed();
      $this->isValid = ($seed && $this->ga->verifyCode($seed, $code, $this->timeSkew));
    }
    return $this->isValid;
  }

  /**
   * @param string $code
   */
  protected function storeAcceptedCode($code) {
    $code = preg_replace('/\s+/', '', $code);
    $hash = hash('sha1', drupal_get_hash_salt() . $code);
    db_insert('tfa_accepted_code')
      ->fields(array(
        'uid' => $this->context['uid'],
        'code_hash' => $hash,
        'time_accepted' => REQUEST_TIME,
      ))
      ->execute();
  }

  /**
   * Whether code has recently been accepted.
   *
   * @param string $code
   * @return bool
   */
  protected function alreadyAcceptedCode($code) {
    $hash = hash('sha1', drupal_get_hash_salt() . $code);
    $result = db_query(
      "SELECT code_hash FROM {tfa_accepted_code} WHERE uid = :uid AND code_hash = :code",
      array(':uid' => $this->context['uid'], ':code' => $hash)
    )->fetchAssoc();
    if (!empty($result)) {
      $this->alreadyAccepted = TRUE;
      return TRUE;
    }
    return FALSE;
  }

  /**
   * Get seed for this account.
   *
   * @return string Decrypted account OTP seed or FALSE if none exists.
   */
  protected function getSeed() {
    // Lookup seed for account and decrypt.
    $result = db_query("SELECT seed FROM {tfa_totp_seed} WHERE uid = :uid", array(':uid' => $this->context['uid']))->fetchAssoc();
    if (!empty($result)) {
      $encrypted = base64_decode($result['seed']);
      $seed = $this->decrypt($encrypted);
      if (!empty($seed)) {
        return $seed;
      }
    }
    return FALSE;
  }

  /**
   * Delete users seeds.
   *
   * @return int
   */
  public function deleteSeed() {
    $query = db_delete('tfa_totp_seed')
      ->condition('uid', $this->context['uid']);

    return $query->execute();
  }
}

/**
 * Class TfaTotpSetup
 */
class TfaTotpSetup extends TfaTotp implements TfaSetupPluginInterface {

  /**
   * @var string Un-encrypted seed.
   */
  protected $seed;

  /**
   * @var string
   */
  protected $namePrefix;

  /**
   * @copydoc TfaBasePlugin::__construct()
   */
  public function __construct(array $context) {
    parent::__construct($context);
    // Generate seed.
    $this->seed = $this->createSeed();
    $this->namePrefix = variable_get('tfa_basic_name_prefix', variable_get('site_name', 'Drupal'));
  }

  /**
   * @copydoc TfaSetupPluginInterface::getSetupForm()
   */
  public function getSetupForm(array $form, array &$form_state) {
    $items = array(
      l('Google Authenticator', 'https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2', array('attributes' => array('target'=>'_blank'))),
      l('Microsoft Authenticator', 'https://www.microsoft.com/hu-hu/p/microsoft-authenticator/9nblgggzmcj6', array('attributes' => array('target'=>'_blank')))
    );
    $form['apps'] = array(
      '#type' => 'markup',
      '#markup' => theme('item_list', array('items' => $items, 'title' => t('Telepíts egy telefonos hitelesítő appot, amennyiben még nincs ilyen a telefonodon:'))),
    );
    $form['info'] = array(
      '#type' => 'markup',
      '#markup' => t('<p>A telefonos hitelesítő appot a kétlépcsős azonosítás beállításához, majd a rendszerbe történő bejelentkezésekkor kell használni. Olvasd be vele a QR kódot, vagy írd be kézzel a szöveges setup kódot.</p>'),
    );
    $form['seed'] = array(
      '#type' => 'textfield',
      '#value' => $this->seed,
      '#disabled' => TRUE,
      '#allow_focus' => TRUE,
      '#description' => t('Olvasd be a telefonos hitelesítő appba a QR kódot, vagy írd be a setup kódot.'),
    );
    // QR image of seed.
    if (file_exists(drupal_get_path('module', 'tfa_basic') . '/includes/qrcodejs/qrcode.min.js')) {
      $form['qr_image_wrapper']['qr_image'] = array(
        '#markup' => '<div id="tfa-qrcode"></div>',
      );
      $qrdata = 'otpauth://totp/' . $this->accountName() . '?secret=' . $this->seed;
      $form['qr_image_wrapper']['qr_image']['#attached']['library'][] = array('tfa_basic', 'qrcodejs');
      $form['qr_image_wrapper']['qr_image']['#attached']['js'][] = array(
        'data' => 'jQuery(document).ready(function () { new QRCode(document.getElementById("tfa-qrcode"), "' . $qrdata . '");});',
        'type' => 'inline',
        'scope' => 'footer',
        'weight' => 5,
      );
    }
    else {
      $form['qr_image'] = array(
        '#markup' => '<img src="' . $this->getQrCodeUrl($this->seed) .'" alt="QR code for TFA setup">',
      );
    }
    // Include code entry form.
    $form = $this->getForm($form, $form_state);
    $form['actions']['login']['#value'] = t('Ellenőriz és ment');
    // Alter code description.
    $form['code']['#description'] = t('Egy 6 számból álló azonosító kód jön jétre, miután a telefonos hitelesítő appba beolvastad a QR kódot, vagy beírtad a setup kódot.');
    return $form;
  }

  /**
   * @copydoc TfaSetupPluginInterface::validateSetupForm()
   */
  public function validateSetupForm(array $form, array &$form_state) {
    if (!$this->validate($form_state['values']['code'])) {
      $this->errorMessages['code'] = t('Érvénytelen azonosító kód. Póbálad meg újra!');
      return FALSE;
    }
    else {
      return TRUE;
    }
  }

  /**
   * @copydoc TfaBasePlugin::validate()
   */
  protected function validate($code) {
    return $this->ga->verifyCode($this->seed, $code, $this->timeSkew);
  }

  /**
   * @copydoc TfaSetupPluginInterface::submitSetupForm()
   */
  public function submitSetupForm(array $form, array &$form_state) {
    // Write seed for user.
    $this->storeSeed($this->seed);
    return TRUE;
  }

  /**
   * Get a URL to a Google Chart QR image for a seed.
   *
   * @param string $seed
   * @return string URL
   */
  protected function getQrCodeUrl($seed) {
    // Note, this URL is over https but does leak the seed and account
    // email address to Google. See README.txt for local QR code generation
    // using qrcode.js.
    return $this->ga->getQRCodeGoogleUrl($this->accountName(), $seed);
  }

  /**
   * Create OTP seed for account.
   *
   * @return string Seed.
   */
  protected function createSeed() {
    return $this->ga->createSecret(24);
  }

  /**
   * Save seed for account.
   *
   * @param string $seed Seed.
   */
  protected function storeSeed($seed) {
    // Encrypt seed for storage.
    $encrypted = $this->encrypt($seed);
    // Data is binary so store base64 encoded.
    $record = array(
      'uid' => $this->context['uid'],
      'seed' => base64_encode($encrypted),
      'created' => REQUEST_TIME
    );

    $existing = $this->getSeed();
    if (!empty($existing)) {
      // Update existing seed.
      drupal_write_record('tfa_totp_seed', $record, 'uid');
    }
    else {
      drupal_write_record('tfa_totp_seed', $record);
    }
  }

  /**
   * Get account name for QR image.
   *
   * @return string URL encoded string.
   */
  protected function accountName() {
    $account = user_load($this->context['uid']);
    return urlencode($this->namePrefix . '-' . $account->name);
  }

}
