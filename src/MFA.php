<?php
declare(strict_types=1);
namespace Security;

use App\Models\Mfa as MfaModel;
use RobThree\Auth\TwoFactorAuth as TFA;


class MFA
{

	/**
	 * @property string $totp_issuer
	 * 
	 * @since   🌱 0.0.0
	 * @version 🌴 0.0.0
	 * @author  ✍ Muhammad Mahmudul Hasan Mithu
	 */
	public string $totp_issuer = '';


	function __construct(public int $user_id, public string $method=''){
		if($method==='totp') $this->totp_issuer = config("security.totp.issuer", 'Unknown');
	}


	/**
	 * get mfa info
	 * 
	 * @return array mfa info
	 * 
	 * @since   🌱 0.0.0
	 * @version 🌴 0.0.0
	 * @author  ✍ Muhammad Mahmudul Hasan Mithu
	 */
	public function status(): array | null
	{
		$status = [
			'is_totp_verified',
			'is_totp_enable',
	
			'email',
			'is_email_verified',
			'is_email_enable',
	
			'phone',
			'is_phone_verified',
			'is_phone_enable',
			
			'created_at',
			'updated_at'
		];
		return MfaModel::where('user_id', $this->user_id)->first($status)?->toArray();
	}


	/**
	 * set new mfa
	 * 
	 * @param string $value
	 * - for totp : the value is email or username
	 * - for email: the value is email
	 * - for phone: the value is phone
	 * 
	 * @return string
	 * - for totp : otpauth qr text
	 * - for email: otp
	 * - for phone: otp
	 * 
	 * @since   🌱 0.0.0
	 * @version 🌴 0.0.0
	 * @author  ✍ Muhammad Mahmudul Hasan Mithu
	 */
	public function setNewMFA(string $value): string|false
	{
		if($this->method==='totp'){
			$totp = new TFA($this->totp_issuer, 6, 30);
			$secret = $totp->createSecret();
			MfaModel::updateOrCreate(
				['user_id'=>$this->user_id],
				[
					'totp'=>$secret,
					'is_totp_verified'=>false,
					'is_totp_enable'=>false
				]
			);
			return $totp->getQRText($value, $secret);
		}

		else if($this->method==='email'){
			MfaModel::updateOrCreate(
				['user_id'=>$this->user_id],
				[
					'email'=>$value,
					'is_email_verified'=>false,
					'is_email_enable'=>false
				]
			);
			return OTP::create('set_mfa_email', $this->user_id);
		}

		else if($this->method==='phone'){
			MfaModel::updateOrCreate(
				['user_id'=>$this->user_id],
				[
					'phone'=>$value,
					'is_phone_verified'=>false,
					'is_phone_enable'=>false
				]
			);
			return OTP::create('set_mfa_phone', $this->user_id);
		}
		return false;
	}


	/**
	 * verify new mfa
	 * 
	 * @param string $otp
	 * 
	 * @return bool bool
	 * 
	 * @since   🌱 0.0.0
	 * @version 🌴 0.0.0
	 * @author  ✍ Muhammad Mahmudul Hasan Mithu
	 */
	public function verifyNewMFA(string $otp): bool
	{

		if($this->method==='totp'){
			$totp = new TFA($this->totp_issuer, 6, 30);
			$secret = MfaModel::where('user_id', $this->user_id)->value('totp');
			if($totp->getCode($secret, time())===$otp || $totp->getCode($secret, time()-30)===$otp || $totp->getCode($secret, time()+30)===$otp){
				MfaModel::where('user_id', $this->user_id)->update([
					'is_totp_verified'=>true,
					'is_totp_enable'=>true
				]);
				return true;
			}
		}

		else if($this->method==='email'){
			if(OTP::validate('set_mfa_email', $this->user_id, $otp)){
				MfaModel::where('user_id', $this->user_id)->update([
					'is_email_verified'=>true,
					'is_email_enable'=>true
				]);
				return true;
			}
		}

		else if($this->method==='phone'){
			if(OTP::validate('set_mfa_phone', $this->user_id, $otp)){
				MfaModel::where('user_id', $this->user_id)->update([
					'is_phone_verified'=>true,
					'is_phone_enable'=>true
				]);
				return true;
			}
		}

		return false;
	}


	/**
	 * create otp
	 * 
	 * @return string|false otp
	 * 
	 * @since   🌱 0.0.0
	 * @version 🌴 0.0.0
	 * @author  ✍ Muhammad Mahmudul Hasan Mithu
	 */
	public function createOTP(): string | false
	{
		$status = self::status();
		if($status){
			if($this->method==='email' && $status['is_email_verified'] && $status['is_email_enable']) return OTP::create('mfa_email_verification', $this->user_id);
			else if($this->method==='phone' && $status['is_phone_verified'] && $status['is_phone_enable']) return OTP::create('mfa_phone_verification', $this->user_id);
		}
		return false;
	}


	/**
	 * verify otp
	 * 
	 * @param string $otp
	 * 
	 * @return bool bool
	 * 
	 * @since   🌱 0.0.0
	 * @version 🌴 0.0.0
	 * @author  ✍ Muhammad Mahmudul Hasan Mithu
	 */
	public function verifyOTP(string $otp): bool
	{
		$status = self::status();
		if($status){

			if($this->method==='totp' && $status['is_totp_verified'] && $status['is_totp_enable']){
				$totp = new TFA($this->totp_issuer, 6, 30);
				$secret = MfaModel::where('user_id', $this->user_id)->value('totp');
				if($totp->getCode($secret, time())===$otp || $totp->getCode($secret, time()-30)===$otp || $totp->getCode($secret, time()+30)===$otp)
				return true;
			}

			if($this->method==='email' && $status['is_email_verified'] && $status['is_email_enable']){
				if(OTP::validate('mfa_email_verification', $this->user_id, $otp)) return true;
			}

			if($this->method==='phone' && $status['is_phone_verified'] && $status['is_phone_enable']){
				if(OTP::validate('mfa_phone_verification', $this->user_id, $otp)) return true;
			}

		}

		return false;
	}


}
