<?php
declare(strict_types=1);
namespace Security;


class Captcha
{


	/**
	 * verify google recaptcha v2
	 * 
	 * @param string $response_id
	 * 
	 * @return bool  true | false
	 *               - true  - if     verified
	 *               - false - if not verified
	 * 
	 * @since   🌱 0.0.0
	 * @version 🌴 0.0.0
	 * @author  ✍ Muhammad Mahmudul Hasan Mithu
	 * 
	 */
	public static function recaptchaV2( string $response_id ): bool
	{
		$key = (object) config("security.captcha.recaptchaV2", [
			'site_key'   => '',
			'secret_key' => ''
		]);

		$url = json_decode(file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret=$key->secret_key&response=$response_id"));
		if( $url->success==true ) return true;

		return false;
	}


}
