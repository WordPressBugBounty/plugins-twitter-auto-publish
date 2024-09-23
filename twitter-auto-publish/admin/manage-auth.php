<?php if( !defined('ABSPATH') ){ exit();}
global $wpdb;
if(isset($_GET['msg']) && $_GET['msg']=='twap_pack_updated'){
	?>
<div class="system_notice_area_style1" id="system_notice_area">
<?php $twap_word_smap="SMAP";
$twap_smap_update_msg=sprintf(__('%s Package updated successfully.','twitter-auto-publish'),$twap_word_smap); 
echo $twap_smap_update_msg; ?>
&nbsp;&nbsp;&nbsp;<span id="system_notice_area_dismiss"><?php _e('Dismiss','twitter-auto-publish'); ?>
</span>
</div>
<?php
}
$free_plugin_source='twap';$xyz_twap_licence_key='';
$domain_name=trim(get_option('siteurl'));
$xyzscripts_hash_val=trim(get_option('xyz_twap_xyzscripts_hash_val'));
$xyzscripts_user_id=trim(get_option('xyz_twap_xyzscripts_user_id'));
$manage_auth_parameters=array(
		'xyzscripts_user_id'=>$xyzscripts_user_id,
		'free_plugin_source'=>$free_plugin_source
);
if ($xyzscripts_user_id=='')
{ ?>
	<b> <?php $twap_word_smapsolution="smapsolutions";
		$twap_smap_auth_msg=sprintf(__('Please authorize %s app under Twitter settings to access this page.','twitter-auto-publish'),$twap_word_smapsolution); 
		echo $twap_smap_auth_msg; ?> </b>
	<?php return;
}
?>
<style type="text/css">
.widefat {border: 1px solid #eeeeee!important;
margin: 0px !important;
border-bottom: 3px solid #00a0d2 !important;
margin-bottom:5px;}

.widefat th {border:1px solid #ffffff !important; background-color:#00a0d2; color:#ffffff; margin:0px !important;  padding-top: 12px;
padding-bottom: 12px;
text-align: left;}

.widefat td, .widefat th {
color:#2f2f2f ;
	padding: 12px 5px;
	margin: 0px;
}

.widefat tr{ border: 1px solid #ddd;}

.widefat tr:nth-child(even){background-color: #dddddd !important;}

.widefat tr:hover {background-color: #cccccc;}


.delete_tw_auth_entry,.delete_inactive_tw_entry{background-color: #00a0d2;
border: none;
padding: 5px 10px;
color: #fff;
border-radius: 2px;
outline:0;
}

.delete_tw_auth_entry:hover{background-color:#008282;}

.select_box
{
display: block;
padding: 10px;
background-color: #ddd;
color: #2f2f2f;
width: 96.8%;
margin-bottom: 1px;
}
.xyz_twap_plan_div{
float:left;
padding-left: 5px;
background-color:#b7b6b6;
border-radius:3px;
padding: 5px;
color: white;
margin-left: 5px;
}
.xyz_twap_plan_label{
	font-size: 15px;
    color: #ffffff;
    font-weight: 500;
    float: left;
    padding: 5px;
    background-color: #30a0d2;
}
</style>
<script type="text/javascript">
jQuery(document).ready(function() {
	//document.getElementById("xyz_twap_default_fbauth_tab").click();	

	jQuery('#tw_auth_entries_div').show();
	jQuery("#tw_show_all").attr('checked', true);
	jQuery("#tw_show_all").click(function(){
		jQuery('#tw_twap_manage_auth_table tr:has(td.tw_diff_domain)').show();
		jQuery('#tw_twap_manage_auth_table tr:has(td.tw_same_domain)').show();
	});
	
	jQuery("#tw_show_same_domain").click(function(){
		jQuery('#tw_twap_manage_auth_table tr:has(td.tw_diff_domain)').hide();
		jQuery('#tw_twap_manage_auth_table tr:has(td.tw_same_domain)').show();
	});
	
	jQuery("#tw_show_diff_domain").click(function(){
		jQuery('#tw_twap_manage_auth_table tr:has(td.tw_diff_domain)').show();
		jQuery('#tw_twap_manage_auth_table tr:has(td.tw_same_domain)').hide();
	});

	jQuery(".delete_tw_auth_entry").off('click').on('click', function() {
	    var tw_auth_id=jQuery(this).attr("data-auth_id");
	    var plugin_src=jQuery(this).attr("data-plugin-src");
	    jQuery("#show-del-icon_"+tw_auth_id).hide();
	    jQuery("#ajax-save_"+tw_auth_id).show();
	    var xyzscripts_user_hash=jQuery(this).attr("data-xyzscripts_hash");
	    var xyzscripts_id=jQuery(this).attr("data-xyzscriptsid");
		var account_id =jQuery(this).attr("data-tw_account_id");
	    var xyz_twap_del_entries_tw_nonce= '<?php echo wp_create_nonce('xyz_twap_del_entries_tw_nonce');?>';
	    var dataString = {
	    	action: 'xyz_twap_del_tw_entries',
	    	tw_auth_id: tw_auth_id ,
	    	account_id: account_id,
	    	xyzscripts_id: xyzscripts_id,
	    	plugin_src:plugin_src,
	    	xyzscripts_user_hash: xyzscripts_user_hash,
	    	dataType: 'json',
	    	_wpnonce: xyz_twap_del_entries_tw_nonce
	    };
	    jQuery.post(ajaxurl, dataString ,function(data) {
	    	jQuery("#ajax-save_"+tw_auth_id).hide();
	    	 if(data==1)
			     alert(xyz_script_twap_var.alert3);
			else{
	    	var data=jQuery.parseJSON(data);
	    	if(data.status==1){
	    		jQuery(".tr_"+tw_auth_id).remove();
	    		if(jQuery('#system_notice_area').length==0)
	    			jQuery('body').append('<div class="system_notice_area_style1" id="system_notice_area"></div>');
	    			jQuery("#system_notice_area").html(xyz_script_twap_var.html1);
	    		 	jQuery("#system_notice_area").append('<span id="system_notice_area_dismiss"><?php _e('Dismiss','twitter-auto-publish'); ?></span>');
	    			jQuery("#system_notice_area").show();
	    			jQuery('#system_notice_area_dismiss').click(function() {
	    				jQuery('#system_notice_area').animate({
	    					opacity : 'hide',
	    					height : 'hide'
	    				}, 500);
	    			});
	    	}
	    	else if(data.status==0 )
	    	{
	    		jQuery("#show_err_"+tw_auth_id).append(data.msg );
	    	}
	    }
	    });
	});
/////////////////////////////////Twitter Ajax//////////////////////////////////////////////				
jQuery("input[name='domain_selection']").click(function(){//show_diff_domain
	numOfVisibleRows = jQuery('#tw_twap_manage_auth_table tr:visible').length;
	//if (this.id == 'show_diff_domain') 
	//	{
		if(numOfVisibleRows==1)
		{	
			jQuery('.xyz_twap_manage_auth_th_tw').hide();
			jQuery('#xyz_twap_no_auth_entries').show();
		}
		else{	
			jQuery('.xyz_twap_manage_auth_th_tw').show();
			jQuery('#xyz_twap_no_auth_entries').hide();
		}
//	}
});		



//////////////////////////////DELETE INACTIVE TW ACCOUNT///////////
jQuery(".delete_inactive_tw_entry").off('click').on('click', function() {
    var inactive_tw_userid=jQuery(this).attr("data-twid");
    var tr_iterationid=jQuery(this).attr("data-tw_iterationid");
    jQuery("#show-del-icon-inactive-tw_"+tr_iterationid).hide();
    jQuery("#ajax-save-inactive-tw_"+tr_iterationid).show();
    var xyzscripts_user_hash=jQuery(this).attr("data-xyzscripts_hash");
    var xyzscripts_id=jQuery(this).attr("data-xyzscriptsid");
    var xyz_twap_del_twuser_entries_nonce= '<?php echo wp_create_nonce('xyz_twap_del_twuser_entries_nonce');?>';
    var dataString = {
    	action: 'xyz_twap_del_twuser_entries',
    	tr_iterationid: tr_iterationid ,
    	xyzscripts_id: xyzscripts_id,
    	xyzscripts_user_hash: xyzscripts_user_hash,
    	inactive_tw_userid: inactive_tw_userid,
    	dataType: 'json',
    	_wpnonce: xyz_twap_del_twuser_entries_nonce
    };
    jQuery.post(ajaxurl, dataString ,function(data) {
    	jQuery("#ajax-save-inactive-tw_"+tr_iterationid).hide();
    	 if(data==1)
		       	alert(xyz_script_twap_var.alert3);
		else{
    	var data=jQuery.parseJSON(data);
    	if(data.status==1){
    		jQuery(".tr_inactive"+tr_iterationid).remove();
    		if(jQuery('#system_notice_area').length==0)
    			jQuery('body').append('<div class="system_notice_area_style1" id="system_notice_area"></div>');
    			jQuery("#system_notice_area").html(xyz_script_twap_var.html2); 
    			jQuery("#system_notice_area").append('<span id="system_notice_area_dismiss"><?php _e('Dismiss','twitter-auto-publish'); ?></span>');
    			jQuery("#system_notice_area").show();
    			jQuery('#system_notice_area_dismiss').click(function() {
    				jQuery('#system_notice_area').animate({
    					opacity : 'hide',
    					height : 'hide'
    				}, 500);
    			});
    	}
    	else if(data.status==0 )
    	{
    		jQuery("#show_err_inactive_tw_"+tr_iterationid).append(data.msg );
    	}
    }
    });
  });
///////////////////////////////////////////////////////////////////
window.addEventListener('message', function(e) {
	ProcessChildMessage_2(e.data);
} , false);
//////////////////////////////////////////////////////////////////
	function ProcessChildMessage_2(message) {
			var obj1=jQuery.parseJSON(message);console.log(message);
		  	if(obj1.twap_api_upgrade && obj1.success_flag){ 
			   var base = '<?php echo admin_url('admin.php?page=twitter-auto-publish-manage-authorizations&msg=twap_pack_updated');?>';
			  window.location.href = base;
			}
	}
///////////////////////////////////////////////////////////////////
});
function twap_popup_purchase_plan(auth_secret_key,request_hash,media)
{
	var account_id=0;
	var xyz_twap_smapsoln_userid=0;
	var childWindow = null;
	var domain_name='<?php echo urlencode($domain_name); ?>';
	var twap_licence_key='<?php echo $xyz_twap_licence_key;?>';
	var smap_solution_url='<?php echo XYZ_TWAP_SMAPSOLUTION_AUTH_URL;?>';
	var xyzscripts_hash_val	='<?php echo $xyzscripts_hash_val;?>';
	var xyzscripts_user_id='<?php echo $xyzscripts_user_id; ?>';
	var twap_plugin_source='<?php echo $free_plugin_source;?>';
	if(media=='twitter')
		childWindow=window.open(smap_solution_url+"authorize-twitter/twitter.php?smap_tw_auth_id="+xyz_twap_smapsoln_userid+"&account_id="+account_id+"&domain_name="+domain_name+"&xyzscripts_user_id="+xyzscripts_user_id+"&request_hash="+request_hash+"&smap_licence_key="+twap_licence_key+"&auth_secret_key="+auth_secret_key+"&free_plugin_source="+twap_plugin_source+"&smap_api_upgrade=1", "SmapSolutions Authorization", "toolbar=yes,scrollbars=yes,resizable=yes,left=500,width=600,height=600");
	
	return false;
}
	</script>
	<div>
	<h3> <?php _e('Manage Authorizations','twitter-auto-publish'); ?></h3>



<div>
	<?php
$url_tw=XYZ_TWAP_SMAPSOLUTION_AUTH_URL.'authorize-twitter/manage-tw-authorizations.php';
$content_tw=xyz_twap_post_to_smap_api($manage_auth_parameters,$url_tw,$xyzscripts_hash_val);
$result_tw=json_decode($content_tw,true);//print_r($result_tw);die;
if(!empty($result_tw) && isset($result_tw['status']))
{
	if($result_tw['status']==0)
	{
	$er_msg=$result_tw['msg'];
	echo '<div style="color:red;font-size:15px;">'.$er_msg.'</div>';
	}
	if($result_tw['status']==1 || isset($result_tw['package_details'])){
		$tw_auth_entries=$result_tw['msg'];
		?>
		<div id="tw_auth_entries_div" style="margin-bottom: 5px;">
					<br/>
					<?php if(!empty($result_tw) && isset($result_tw['package_details']))
					{
						?><div class="xyz_twap_plan_label"> <?php _e('Current Plan:','twitter-auto-publish'); ?></div><?php 
						$tw_package_details=$result_tw['package_details'];?>
						<div class="xyz_twap_plan_div"> <?php _e('Allowed Twitter users:','twitter-auto-publish'); ?> <?php echo $tw_package_details['allowed_tw_user_accounts'];?> &nbsp;</div>
						<div  class="xyz_twap_plan_div"> <?php _e('API limit per account :','twitter-auto-publish'); ?> <?php echo $tw_package_details['allowed_twapi_calls'];_e('per day','twitter-auto-publish'); ?> &nbsp;</div>
						<div  class="xyz_twap_plan_div"> <?php _e('Package Expiry :','twitter-auto-publish'); ?> <?php echo date('d/m/Y g:i a', $tw_package_details['tw_expiry_time']);?>  &nbsp;</div>
						<div  class="xyz_twap_plan_div"> <?php _e('Package Status :','twitter-auto-publish'); ?> <?php echo $tw_package_details['package_status'];?> &nbsp;</div>
						<?php 
// 						if ($tw_package_details['package_status']=='Expired')
						{
							$xyz_twap_accountId=$xyz_smap_smapsoln_userid=0; 
							$request_hash=md5($xyzscripts_user_id.$xyzscripts_hash_val);
							$auth_secret_key=md5('smapsolutions'.$domain_name.$xyz_twap_accountId.$xyz_smap_smapsoln_userid.$xyzscripts_user_id.$request_hash.$xyz_twap_licence_key.$free_plugin_source.'1');
							?>
							<div  class="xyz_twap_plan_div">
							<a href="javascript:twap_popup_purchase_plan('<?php echo $auth_secret_key;?>','<?php echo $request_hash;?>','twitter');void(0);">
							<i class="fa fa-shopping-cart" aria-hidden="true"></i>&nbsp; <?php _e('Upgrade/Renew','twitter-auto-publish'); ?>
							</a> 
							</div>
							<?php 
						}
					}
					if (is_array($tw_auth_entries) && !empty($tw_auth_entries)){
					?><br/>
						<span class="select_box"  style="float: left;margin-top: 16px;" >
						<input type="radio" name="tw_domain_selection" value="0" id="tw_show_all"> <?php _e('Show all entries','twitter-auto-publish'); ?>
						<input type="radio" name="tw_domain_selection" value="1" id="tw_show_same_domain"> <?php _e('Show entries from current wp installation','twitter-auto-publish'); ?>
						<input type="radio" name="tw_domain_selection" value="2" id="tw_show_diff_domain" > <?php _e('Show entries from other wp installations','twitter-auto-publish'); ?>
						</span>
						<table cellpadding="0" cellspacing="0" class="widefat" style="width: 99%; margin: 0 auto; border-bottom:none;" id="tw_twap_manage_auth_table">
						<thead>
						<tr class="xyz_twap_manage_auth_th_tw">
						<th scope="col" width="13%"><?php _e('Twitter user name','twitter-auto-publish'); ?></th>
						
<!-- 						<th scope="col" width="10%"><?php _e('Selected groups','twitter-auto-publish'); ?></th> -->
						<th scope="col" width="10%"><?php $twap_wp="WP";
						   				  $twap_wp_url=sprintf(__('%s url','twitter-auto-publish'),$twap_wp); 
						 			          echo $twap_wp_url; ?> </th>
						<th scope="col" width="10%"> <?php _e('Plugin','twitter-auto-publish'); ?></th>
						<th scope="col" width="5%"> <?php $twap_smap_premium_var="(SMAP PREMIUM)"; $twap_smap_premium_title= sprintf(__('Account ID %s','twitter-auto-publish'),$twap_smap_premium_var); 
						                                  echo $twap_smap_premium_title; ?> </th>
						<th scope="col" width="5%"> <?php _e('Action','twitter-auto-publish'); ?></th>
						</tr>
						</thead> <?php
						$i=0;
						foreach ($tw_auth_entries as $tw_auth_entries_key => $tw_auth_entries_val)
						{ 
							    if (isset($tw_auth_entries_val['tw_username'])){
							?>
							 <tr class="tr_<?php echo $tw_auth_entries_val['auth_id'];?>">
							 <td><?php  echo $tw_auth_entries_val['tw_username'];?>
							 	</td>
							 	<?php 	if($tw_auth_entries_val['domain_name']==$domain_name){?>
							 	<td class='tw_same_domain'> <?php echo $tw_auth_entries_val['domain_name'];?> </td>
							 	<?php }
							 	else{?>
							 	<td class='tw_diff_domain'> <?php echo $tw_auth_entries_val['domain_name'];?> </td>
							 	<?php } ?>
							 	<td> <?php
							 	if($tw_auth_entries_val['free_plugin_source']=='twap')
							 		echo 'WP TWITTER AUTO PUBLISH';
							 		elseif ($tw_auth_entries_val['free_plugin_source']=='smap')
							 		echo 'SOCIAL MEDIA AUTO PUBLISH';
							 		elseif ($tw_auth_entries_val['free_plugin_source']=='pls')
							 		echo 'XYZ WP SMAP Premium Plus';
							 		else echo 'XYZ WP SMAP Premium';
							 		?></td>
							 		<td> <?php if($tw_auth_entries_val['smap_pre_account_id']!=0){echo $tw_auth_entries_val['smap_pre_account_id'];}
							 		else _e('Not Applicable','twitter-auto-publish');?> </td>
							 		<td>
							 		<?php
							 		if ($domain_name==$tw_auth_entries_val['domain_name'] && $free_plugin_source==$tw_auth_entries_val['free_plugin_source'] ) {
							 		?>
							 		<span id='ajax-save_<?php echo $tw_auth_entries_val['auth_id'];?>' style="display:none;"><img	title="Deleting entry"	src="<?php echo plugins_url("images/ajax-loader.gif",XYZ_TWAP_PLUGIN_FILE);?>" style="width:20px;height:20px; "/></span>
							 		<span id='show-del-icon_<?php echo $tw_auth_entries_val['auth_id'];?>'>
							 		<input type="button" class="delete_tw_auth_entry" data-auth_id=<?php echo $tw_auth_entries_val['auth_id'];?> data-tw_account_id=<?php echo $tw_auth_entries_val['smap_pre_account_id'];?>   data-plugin-src=<?php echo $tw_auth_entries_val['free_plugin_source'];?> data-xyzscriptsid="<?php echo $xyzscripts_user_id;?>" data-xyzscripts_hash="<?php echo $xyzscripts_hash_val;?>" name='del_tw_entry' value="<?php _e('Delete','twitter-auto-publish'); ?>" >
							 		</span>
							 		<span id='show_err_<?php echo $tw_auth_entries_val['auth_id'];?>' style="color:red;" ></span>
							 		<?php
							 		?></td>
							 		</tr>
							 		<?php
							 		}
							}
							else if (isset($tw_auth_entries_val['inactive_tw_userid']))
							{
								?>
						 <tr class="tr_inactive<?php echo $i;?>">
						 <td><?php  echo $tw_auth_entries_val['inactive_tw_username'];?><br/> <?php _e('(Inactive)','twitter-auto-publish'); ?>
						 </td>
						 <td>-</td>
						 <td>-</td>
						 <td>-</td>
						 <td>-</td>
						 <td>
						 <span id='ajax-save-inactive-tw_<?php echo $i;?>' style="display:none;"><img	title="Deleting entry"	src="<?php echo plugins_url("images/ajax-loader.gif",XYZ_TWAP_PLUGIN_FILE);?>" style="width:20px;height:20px; "></span>
						 <span id='show-del-icon-inactive-tw_<?php echo $i;?>'>
						 <input type="button" class="delete_inactive_tw_entry" data-tw_iterationid=<?php echo $i;?> data-twid=<?php echo $tw_auth_entries_val['inactive_tw_userid'];?>  data-xyzscriptsid="<?php echo $xyzscripts_user_id;?>" data-xyzscripts_hash="<?php echo $xyzscripts_hash_val;?>" name='del_entry' value="<?php _e('Delete','twitter-auto-publish');?>" >
						 </span>
						 <span id='show_err_inactive_tw_<?php echo $i;?>' style="color:red;" ></span>
						 </td>
						 </tr>
						<?php 
							$i++;
						}
						}///////////////foreach
					?>
					<tr id="xyz_twap_no_auth_entries_tw" style="display: none;"><td> <?php _e('No Authorizations','twitter-auto-publish'); ?></td></tr>
					</table>
					<br/>
	<?php  }?>
					</div>	<br/><?php
}
}
else { ?>
	<div> <?php _e('Unable to connect. Please check your curl and firewall settings','twitter-auto-publish'); ?> </div>
<?php }
?>
</div>
</div>