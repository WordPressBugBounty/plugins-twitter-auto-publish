<?php
if( !defined('ABSPATH') ){ exit();}
function twap_free_network_install($networkwide) {
	global $wpdb;

	if (function_exists('is_multisite') && is_multisite()) {
		// check if it is a network activation - if so, run the activation function for each blog id
		if ($networkwide) {
			$old_blog = $wpdb->blogid;
			// Get all blog ids
			$blogids = $wpdb->get_col("SELECT blog_id FROM $wpdb->blogs");
			foreach ($blogids as $blog_id) {
				switch_to_blog($blog_id);
				twap_install_free();
			}
			switch_to_blog($old_blog);
			return;
		}
	}
	twap_install_free();
}

function twap_install_free()
{
	/*$pluginName = 'xyz-wp-smap/xyz-wp-smap.php';
	if (is_plugin_active($pluginName)) {
		wp_die( "The plugin Twitter Auto Publish cannot be activated unless the premium version of this plugin is deactivated. Back to <a href='".admin_url()."plugins.php'>Plugin Installation</a>." );
	}*/
	
	global $current_user;
	wp_get_current_user();
	if(get_option('xyz_credit_link')=="")
	{
		add_option("xyz_credit_link", '0');
	}
	
	$twap_installed_date = get_option('twap_installed_date');
	if ($twap_installed_date=="") {
		$twap_installed_date = time();
		update_option('twap_installed_date', $twap_installed_date);
	}

	add_option('xyz_twap_twconsumer_secret', '');
	add_option('xyz_twap_twconsumer_id','');
	add_option('xyz_twap_client_id', '');//auth2.0
	add_option('xyz_twap_client_secret','');//auth2.0
	add_option('xyz_twap_tw_id', '');
	add_option('xyz_twap_current_twappln_token', '');
	add_option('xyz_twap_twpost_permission', '1');
	add_option('xyz_twap_twpost_image_permission', '1');
	add_option('xyz_twap_twaccestok_secret', '');
	add_option('xyz_twap_twmessage', '{POST_TITLE} - {PERMALINK}');
	add_option('xyz_twap_future_to_publish', '1');
	add_option('xyz_twap_apply_filters', '');
	
	
	$version=get_option('xyz_twap_free_version');
	$currentversion=xyz_twap_plugin_get_version();
	update_option('xyz_twap_free_version', $currentversion);
	
	add_option('xyz_twap_include_pages', '0');
	add_option('xyz_twap_include_posts', '1');
	add_option('xyz_twap_include_categories', 'All');
	add_option('xyz_twap_include_customposttypes', '');
	add_option('xyz_twap_peer_verification', '1');
	add_option('xyz_twap_post_logs', '');
	add_option('xyz_twap_premium_version_ads', '1');
	add_option('xyz_twap_default_selection_edit', '0');
	add_option('xyz_twap_default_selection_create', '1');
	add_option('xyz_twap_tw_char_limit',280);
	add_option('xyz_twap_credit_dismiss','0');
	if (get_option('xyz_twap_tw_enforce_twitter_cards') === false){
	update_option('xyz_twap_tw_enforce_twitter_cards', get_option('xyz_smap_free_enforce_twitter_cards') ? 1 : 0);
	}
	add_option('xyz_twap_tw_token', '');
	add_option('xyz_twap_tw_refresh_token','');
	add_option('xyz_twap_last_auth_time','');
	add_option('xyz_twap_tw_af',1);
	
	$xyz_twap_include_categories=get_option('xyz_twap_include_categories');
	if ( is_array($xyz_twap_include_categories) )
	{
	$xyz_twap_include_categories=implode(",",$xyz_twap_include_categories);
	update_option('xyz_twap_include_categories', $xyz_twap_include_categories);
	}
//$xyz_twap_current_twappln_token= get_option('xyz_twap_current_twappln_token');
//	if ($xyz_twap_current_twappln_token!="")
		add_option('xyz_twap_tw_app_sel_mode','0');//if already publishing using own app
	//else
//		add_option('xyz_twap_tw_app_sel_mode','1');//for new users set smap app as default Application Selection
	add_option('xyz_twap_smapsoln_userid','0');
	add_option('xyz_twap_smapsoln_secret_key','');
	add_option('xyz_twap_xyzscripts_user_id','');
	add_option('xyz_twap_xyzscripts_hash_val','');
}


register_activation_hook(XYZ_TWAP_PLUGIN_FILE,'twap_free_network_install');
?>
