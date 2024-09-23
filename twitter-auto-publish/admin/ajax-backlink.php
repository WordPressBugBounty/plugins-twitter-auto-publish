<?php
if( !defined('ABSPATH') ){ exit();}
add_action('wp_ajax_xyz_twap_ajax_backlink', 'xyz_twap_ajax_backlink_call');

function xyz_twap_ajax_backlink_call() {


	global $wpdb;

	if($_POST){
		if (! isset( $_POST['_wpnonce'] )|| ! wp_verify_nonce( $_POST['_wpnonce'],'backlink' ))
		 {
					echo 1;die;
		 }
		 if(current_user_can('administrator')){
		 	global $wpdb;
		 	if(isset($_POST)){
		 		if(intval($_POST['enable'])==1){
		 			update_option('xyz_credit_link','twap');
		 			echo "twap";
				}
		 		if(intval($_POST['enable'])==-1){
		 			update_option('xyz_twap_credit_dismiss', "dis");
		 			echo -1;
		 		}
		 	}
		 }
	}
	die();
}

add_action('wp_ajax_xyz_twap_xyzscripts_accinfo_auto_update', 'xyz_twap_xyzscripts_accinfo_auto_update_fn');
function xyz_twap_xyzscripts_accinfo_auto_update_fn() {
	global $wpdb;
	if(current_user_can('administrator')){
		if($_POST){
			if (! isset( $_POST['_wpnonce'] )|| ! wp_verify_nonce( $_POST['_wpnonce'],'xyz_twap_xyzscripts_accinfo_nonce' ))
			{
				echo 1;die;
			}
			global $wpdb;
			if(isset($_POST)){
				$xyzscripts_hash_val=stripslashes($_POST['xyz_user_hash']);
				$xyzscripts_user_id=$_POST['xyz_userid'];
				update_option('xyz_twap_xyzscripts_user_id', $xyzscripts_user_id);
				update_option('xyz_twap_xyzscripts_hash_val', $xyzscripts_hash_val);
			}
		}
	}
	die();
}
////////////////////////////////////twitter ////////////////////////////////////////////////
add_action('wp_ajax_xyz_twap_tw_account_details_auto_update', 'xyz_twap_tw_account_details_auto_update_fn');
function xyz_twap_tw_account_details_auto_update_fn() {
	global $wpdb;
	if(current_user_can('administrator')){
		if($_POST){
			if (! isset( $_POST['_wpnonce'] )|| ! wp_verify_nonce( $_POST['_wpnonce'],'xyz_twap_tw_account_details_nonce' ))
			{
				echo -1;die;
			}
			global $wpdb;
			if(isset($_POST)){
				$twap_sec_key=$_POST['twap_secretkey'];
				$xyzscripts_user_id=$_POST['xyz_twap_xyzscripts_user_id'];
				$xyzscripts_hash_val=$_POST['xyz_twap_xyzscripts_hash_val'];
				$xyz_twap_smapsoln_userid=$_POST['smapsoln_userid'];
// 				$xyz_tw_user_id=$_POST['xyz_tw_user_id'];
				$xyz_tw_username=$_POST['xyz_tw_username'];
				update_option('xyz_twap_xyzscripts_user_id', $xyzscripts_user_id);
				update_option('xyz_twap_xyzscripts_hash_val', $xyzscripts_hash_val);
				update_option('xyz_twap_smapsoln_secret_key', $twap_sec_key);
				update_option('xyz_twap_smapsoln_userid', $xyz_twap_smapsoln_userid);
				update_option('xyz_twap_tw_id', $xyz_tw_username);
			}
		}
	}
	die();
}
/////////////////////////////////////////////////////////////////////////////////////////////////
add_action('wp_ajax_xyz_twap_del_twuser_entries', 'xyz_twap_del_twuser_entries_fn');
function xyz_twap_del_twuser_entries_fn() {
	global $wpdb;
	if(current_user_can('administrator')){
		if($_POST){
			if (! isset( $_POST['_wpnonce'] )|| ! wp_verify_nonce( $_POST['_wpnonce'],'xyz_twap_del_twuser_entries_nonce' ))
			{
				echo 1;die;
			}
			$inactive_tw_userid=$_POST['inactive_tw_userid'];
			$xyz_twap_xyzscripts_user_id = $_POST['xyzscripts_id'];
			$xyz_twap_xyzscripts_hash_val= $_POST['xyzscripts_user_hash'];
			$delete_entry_details=array('tw_userid'=>$inactive_tw_userid,
					'xyzscripts_user_id' =>$xyz_twap_xyzscripts_user_id);
			$url=XYZ_TWAP_SMAPSOLUTION_AUTH_URL.'authorize-twitter/delete-tw-auth.php';
			$content=xyz_twap_post_to_smap_api($delete_entry_details, $url,$xyz_twap_xyzscripts_hash_val);
			echo $content;
		}
	}
	die();
}

add_action('wp_ajax_xyz_twap_del_tw_entries', 'xyz_twap_del_entries_tw_fn');
function xyz_twap_del_entries_tw_fn() {
	global $wpdb;
	if(current_user_can('administrator')){
		if($_POST){
			if (! isset( $_POST['_wpnonce'] )|| ! wp_verify_nonce( $_POST['_wpnonce'],'xyz_twap_del_entries_tw_nonce' ))
			{
				echo 1;die;
			}
			$tw_auth_id=$_POST['tw_auth_id'];
			$xyz_twap_xyzscripts_user_id = $_POST['xyzscripts_id'];
			$xyz_twap_xyzscripts_hash_val= $_POST['xyzscripts_user_hash'];
			$delete_entry_details=array('smap_tw_auth_id'=>$tw_auth_id,
					'xyzscripts_user_id' =>$xyz_twap_xyzscripts_user_id);
			$url=XYZ_TWAP_SMAPSOLUTION_AUTH_URL.'authorize-twitter/delete-tw-auth.php';
			$content=xyz_twap_post_to_smap_api($delete_entry_details, $url,$xyz_twap_xyzscripts_hash_val);
			echo $content;
			$result=json_decode($content);$delete_flag=0;
			if(!empty($result))
			{
				if (isset($result->status))
					$delete_flag =$result->status;
			}
			if ($delete_flag===1)
			{
				if ($tw_auth_id==get_option('xyz_twap_smapsoln_userid')){
					update_option('xyz_twap_smapsoln_secret_key', '');
					update_option('xyz_twap_smapsoln_userid', 0);
				}
			}
		}
	}
	die();
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////
?>