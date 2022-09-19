<?php
declare(strict_types=1);
namespace Security;

use App\Models\Otp as OtpModel;


class OTP
{


	/**
	 * generate otp
	 * 
	 * @param string $purpose
	 * @param int $user_id
	 * @param int $digit (optional). default is 6
	 * 
	 * @return string otp
	 * 
	 * @since   🌱 0.0.0
	 * @version 🌴 0.0.0
	 * @author  ✍ Muhammad Mahmudul Hasan Mithu
	 */
	public static function create( string $purpose, int $user_id, int $digit=6 ): string
	{
		$otp='';
		for($i=0; $i<$digit; $i++) $otp.=rand(1,9);
		// remove unused otp
		OtpModel::where([
				'purpose' => $purpose,
				'user_id' => $user_id,
				'is_used' => false,
			])
			->delete();
		// save otp in the db
		$model_otp = new OtpModel();
		$model_otp->purpose = $purpose;
		$model_otp->user_id = $user_id;
		$model_otp->otp = $otp;
		$model_otp->is_used = false;
		$model_otp->attempt = 0;
		$model_otp->save();
		return $otp;
	}


	/**
	 * validate otp
	 * 
	 * @param string $purpose
	 * @param int $user_id
	 * @param string $otp
	 * 
	 * @return bool check otp is valid or not
	 *              - false, otp is invalid
	 *              - true,  otp is valid
	 * 
	 * @since   🌱 0.0.0
	 * @version 🌴 0.0.0
	 * @author  ✍ Muhammad Mahmudul Hasan Mithu
	 */
	public static function validate(string $purpose, int $user_id, string $otp): bool
	{
		$db_otp =
		OtpModel::where(function($q)use($purpose, $user_id){
			$q->where('purpose', $purpose);
			$q->where('user_id', $user_id);
			$q->where('attempt', '<', 11);
			$q->where('is_used', false);
		})->orderBy('id', 'desc')->get()[0] ?? null;
		if($db_otp){
			if($db_otp->otp===$otp){
				OtpModel::where('id', $db_otp->id)->update(['is_used' => true]);
				return true;
			} else OtpModel::where('id', $db_otp->id)->increment('attempt', 1);
		}

		return false;
	}


}
