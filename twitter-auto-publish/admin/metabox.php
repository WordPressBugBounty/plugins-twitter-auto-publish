<?php 
if( !defined('ABSPATH') ){ exit();}
add_action( 'add_meta_boxes', 'xyz_twap_add_custom_box' );
$GLOBALS['edit_flag']=0;
function xyz_twap_add_custom_box()
{
	$posttype="";
	if(isset($_GET['post_type']))
		$posttype=$_GET['post_type'];
	
	if($posttype=="")
		$posttype="post";
	
if(isset($_GET['action']) && $_GET['action']=="edit" && !empty($_GET['post'])) /// empty check added for fixing client scenario
	{
		$postid=intval($_GET['post']);
		
		
		$get_post_meta=get_post_meta($postid,"xyz_twap",true);
		if($get_post_meta==1){
			$GLOBALS['edit_flag']=1;
		}
		global $wpdb;
		$table='posts';
		$accountCount = $wpdb->query($wpdb->prepare( 'SELECT * FROM '.$wpdb->prefix.$table.' WHERE id=%d and post_status NOT IN (%s, %s) LIMIT %d,%d',array($postid,'draft','future',0,1) )) ;
		//$accountCount = $wpdb->query($wpdb->prepare( 'SELECT * FROM '.$wpdb->prefix.$table.' WHERE id=%d and post_status!=%s LIMIT %d,%d',array($postid,'draft',0,1) )) ;
		if($accountCount>0){
			$GLOBALS['edit_flag']=1;
			}
		$posttype=get_post_type($postid);
	}


	if ($posttype=="page")
	{

		$xyz_twap_include_pages=get_option('xyz_twap_include_pages');
		if($xyz_twap_include_pages==0)
			return;
	}
	else if($posttype=="post")
	{ 
		$xyz_twap_include_posts=get_option('xyz_twap_include_posts');
		if($xyz_twap_include_posts==0)
			return;
	}
	else if($posttype!="post")
	{

		$xyz_twap_include_customposttypes=get_option('xyz_twap_include_customposttypes');


		$carr=explode(',', $xyz_twap_include_customposttypes);
		if(!in_array($posttype,$carr))
			return;

	}
	$tw_af=get_option('xyz_twap_tw_af');
	$xyz_twap_tw_app_sel_mode=get_option('xyz_twap_tw_app_sel_mode');
	$xyz_twap_smapsoln_userid=get_option('xyz_twap_smapsoln_userid');
	if((get_option('xyz_twap_client_id')!="" && get_option('xyz_twap_client_secret')!="" && $tw_af!=1 && $xyz_twap_tw_app_sel_mode==2) || ((get_option('xyz_twap_twconsumer_id')!="" && get_option('xyz_twap_twconsumer_secret')!="" && get_option('xyz_twap_tw_id')!="" && get_option('xyz_twap_current_twappln_token')!="" && get_option('xyz_twap_twaccestok_secret')!="" && $xyz_twap_tw_app_sel_mode==0 )|| ( $xyz_twap_tw_app_sel_mode==1 && !empty($xyz_twap_smapsoln_userid))) && get_option('xyz_twap_twpost_permission')==1)
	add_meta_box( "xyz_twap", '<strong>WP Twitter Auto Publish </strong>', 'xyz_twap_addpostmetatags') ;
}
function xyz_twap_addpostmetatags()
{
	$imgpath= plugins_url()."/twitter-auto-publish/images/";
	$heimg=$imgpath."support.png";
	$xyz_twap_catlist=get_option('xyz_twap_include_categories');
// 	if (is_array($xyz_twap_catlist))
// 		$xyz_twap_catlist=implode(',', $xyz_twap_catlist);
	?>
<script>
function displaycheck_twap()
{
var tcheckid=jQuery("input[name='xyz_twap_twpost_permission']:checked").val();
if(tcheckid==1)
{

	document.getElementById("twmf_twap").style.display='';
	document.getElementById("twmftarea_twap").style.display='';
	document.getElementById("twai_twap").style.display='';	
}
else
{
	
	document.getElementById("twmf_twap").style.display='none';
	document.getElementById("twmftarea_twap").style.display='none';
	document.getElementById("twai_twap").style.display='none';		
}


}


</script>
<script type="text/javascript">
function detdisplay_twap(id)
{
	document.getElementById(id).style.display='';
}
function dethide_twap(id)
{
	document.getElementById(id).style.display='none';
}


jQuery(document).ready(function() {
	displaycheck_twap();
	
	 var xyz_twap_twpost_permission=jQuery("input[name='xyz_twap_twpost_permission']:checked").val();
	 XyzTwapToggleRadio(xyz_twap_twpost_permission,'xyz_twap_twpost_permission'); 
	var wp_version='<?php echo XYZ_TWAP_WP_VERSION; ?>';
	if (wp_version <= '5.3') {
	jQuery('#category-all').bind("DOMSubtreeModified",function(){
		twap_get_categorylist(1);
		});
	
	twap_get_categorylist(1);twap_get_categorylist(2);
	jQuery('#category-all').on("click",'input[name="post_category[]"]',function() {
		twap_get_categorylist(1);
				});

	jQuery('#category-pop').on("click",'input[type="checkbox"]',function() {
		twap_get_categorylist(2);
				});
	/////////gutenberg category selection
	jQuery(document).on('change', 'input[type="checkbox"]', function() {
		twap_get_categorylist(2);
				});
		}
});

/****************** Code to reload metabox content in Gutenberg editor ******************/
jQuery(document).ready(function($) {
// Check if the document body is available and if we're on a block editor page
const isBlockEditorPage = document.body && document.body.classList.contains('block-editor-page');
// Ensure wp and necessary methods are available
if (isBlockEditorPage && 
	typeof wp !== 'undefined' && 
	wp.blocks && 
	wp.data && 
	typeof wp.data.select('core/notices') === 'object' && 
	typeof wp.data.select('core/editor') === 'object' && 
	typeof wp.data.select('core/editor').getCurrentPost === 'function' &&
	typeof wp.data.select('core/notices').getNotices === 'function') {
		wp.data.subscribe(() => { 
		const notices = wp.data.select( 'core/notices' ).getNotices(); 
		const publishSuccessNotice = notices.find( notice => notice.content === 'Post published.' || notice.content === 'Post updated.');
		const editorSelect = wp.data.select('core/editor');
            if (editorSelect && typeof editorSelect.getCurrentPost === 'function') {
		const currentPostStatus = wp.data.select('core/editor').getCurrentPost().status;
		if (publishSuccessNotice && currentPostStatus === 'publish') 
			{
                    var xyz_twap_default_selection_edit="<?php echo esc_html(get_option('xyz_twap_default_selection_edit'));?>";
                    if(xyz_twap_default_selection_edit==0 && jQuery("input[name='xyz_twap_twpost_permission']:checked").val()==1) {
                      document.getElementById("twmf_twap").style.display='none';
                    	document.getElementById("twmftarea_twap").style.display='none';
                    	document.getElementById("twai_twap").style.display='none';
                    	jQuery('#xyz_twap_twpost_permission_0').prop('checked',true);
                    	jQuery('#xyz_twap_twpost_permission_yes').removeClass('xyz_twap_toggle_on');
                    	jQuery('#xyz_twap_twpost_permission_yes').addClass('xyz_twap_toggle_off');
                    	jQuery('#xyz_twap_twpost_permission_no').removeClass('xyz_twap_toggle_off');
                    	jQuery('#xyz_twap_twpost_permission_no').addClass('xyz_twap_toggle_on');
                    }
                    else if(xyz_twap_default_selection_edit==1 && jQuery("input[name='xyz_twap_twpost_permission']:checked").val()==0) {
                    	document.getElementById("twmf_twap").style.display='';
                    	document.getElementById("twmftarea_twap").style.display='';
                    	document.getElementById("twai_twap").style.display='';
                    	jQuery('#xyz_twap_twpost_permission_1').prop('checked',true);
                    	jQuery('#xyz_twap_twpost_permission_no').removeClass('xyz_twap_toggle_on');
                    	jQuery('#xyz_twap_twpost_permission_no').addClass('xyz_twap_toggle_off');
                    	jQuery('#xyz_twap_twpost_permission_yes').removeClass('xyz_twap_toggle_off');
                    	jQuery('#xyz_twap_twpost_permission_yes').addClass('xyz_twap_toggle_on');
                    }
                }
        }
		});
	}
});
/*************************************************************************************/
function twap_get_categorylist(val)
{
	var flag=true;
	var cat_list="";var chkdArray=new Array();var cat_list_array=new Array();
	var posttype="<?php echo get_post_type() ;?>";
	if(val==1){
	 jQuery('input[name="post_category[]"]:checked').each(function() {
		 cat_list+=this.value+",";flag=false;
		});
	}else if(val==2)
	{
		jQuery('#category-pop input[type="checkbox"]:checked').each(function() {
			cat_list+=this.value+",";flag=false;
		});
		jQuery('.editor-post-taxonomies__hierarchical-terms-choice input[type="checkbox"]:checked').each(function() { //gutenberg category checkbox
			cat_list+=this.value+",";flag=false;
		});
		if(flag){
		<?php
		if (isset($_GET['post']))
			$postid=intval($_GET['post']);
		if (isset($GLOBALS['edit_flag']) && $GLOBALS['edit_flag']==1 && !empty($postid)){
			$defaults = array('fields' => 'ids');
			$categ_arr=wp_get_post_categories( $postid, $defaults );
			$categ_str=implode(',', $categ_arr);
			?>
			cat_list+='<?php echo $categ_str; ?>';
					<?php }?> flag=false;
			
		}
	}
	 if (cat_list.charAt(cat_list.length - 1) == ',') {
		 cat_list = cat_list.substr(0, cat_list.length - 1);
		}
		jQuery('#cat_list').val(cat_list);
		
		var xyz_twap_catlist="<?php echo $xyz_twap_catlist;?>";
		if(xyz_twap_catlist!="All")
		{
			cat_list_array=xyz_twap_catlist.split(',');
			var show_flag=1;
			var chkdcatvals=jQuery('#cat_list').val();
			chkdArray=chkdcatvals.split(',');
			
			for(var x=0;x<chkdArray.length;x++) { 
				
				if(inArray(chkdArray[x], cat_list_array))
				{
					show_flag=1;
					break;
				}
				else
				{
					show_flag=0;
					continue;
				}
				
			}

			if(show_flag==0 && posttype=="post")
				jQuery('#xyz_twMetabox').hide();
			else
				jQuery('#xyz_twMetabox').show();
		}
}
function inArray(needle, haystack) {
    var length = haystack.length;
    for(var i = 0; i < length; i++) {
        if(haystack[i] == needle) return true;
    }
    return false;
}


</script>
<table class="xyz_twap_metalist_table">
<input type="hidden" name="cat_list" id="cat_list" value="">
<input type="hidden" name="xyz_twap_post" id="xyz_twap_post" value="0" >
	<tr id="xyz_twMetabox"><td colspan="2" >
<?php 
$xyz_twap_tw_af=get_option('xyz_twap_tw_af');
$xyz_twap_tw_token=get_option('xyz_twap_tw_token');
$taccess_token_secret=get_option('xyz_twap_twaccestok_secret');
$xyz_twap_tw_app_sel_mode=get_option('xyz_twap_tw_app_sel_mode');
$xyz_twap_smapsoln_userid=get_option('xyz_twap_smapsoln_userid');
if(get_option('xyz_twap_twpost_permission')==1 && ($xyz_twap_tw_app_sel_mode==1 && !empty($xyz_twap_smapsoln_userid)) || ($xyz_twap_tw_app_sel_mode==0 && !empty($taccess_token_secret))|| ($xyz_twap_tw_app_sel_mode==2 && !empty($xyz_twap_tw_token) && $xyz_twap_tw_af!=1))
{
	$postid=0;
if (isset($_GET['post']))
	$postid=intval($_GET['post']);
$post_permission=1;
$get_post_meta_future_data='';
$get_post_meta=get_post_meta($postid,"xyz_twap",true);
if (((get_option('xyz_twap_default_selection_edit')==2 && isset($GLOBALS['edit_flag']) && $GLOBALS['edit_flag']==1) || ((get_option('xyz_twap_default_selection_create')==2) && $get_post_meta!=1 && $GLOBALS['edit_flag']!=1))  && !empty($postid))
	$get_post_meta_future_data=get_post_meta($postid,"xyz_twap_future_to_publish",true);
	if (!empty($get_post_meta_future_data)&& isset($get_post_meta_future_data['xyz_twap_twpost_permission']))
	{
		$post_permission=$get_post_meta_future_data['xyz_twap_twpost_permission'];
		$post_twitter_image_permission=$get_post_meta_future_data['xyz_twap_twpost_image_permission'];
		$messagetopost=$get_post_meta_future_data['xyz_twap_twmessage'];
	}
	else {
		$post_twitter_image_permission=get_option('xyz_twap_twpost_image_permission');
		$messagetopost=get_option('xyz_twap_twmessage');
	}
?>
<table class="xyz_twap_meta_acclist_table"><!-- TW META -->


<tr>
		<td colspan="2" class="xyz_twap_pleft15 xyz_twap_meta_acclist_table_td"><strong><?php _e('Twitter','twitter-auto-publish'); ?></strong>
		</td>
</tr>

<tr><td colspan="2" valign="top">&nbsp;</td></tr>

	<tr valign="top">
		<td class="xyz_twap_pleft15" width="60%"><?php _e('Enable auto publish posts to my twitter account','twitter-auto-publish'); ?>
		</td>
		<td  class="xyz_twap_switch_field">
		<label id="xyz_twap_twpost_permission_yes"><input type="radio" name="xyz_twap_twpost_permission" id="xyz_twap_twpost_permission_1" value="1" <?php  if($post_permission==1) echo 'checked';?>/><?php _e('Yes','twitter-auto-publish'); ?></label>
		<label id="xyz_twap_twpost_permission_no"><input type="radio" name="xyz_twap_twpost_permission" id="xyz_twap_twpost_permission_0" value="0" <?php  if($post_permission==0) echo 'checked';?>/><?php _e('No','twitter-auto-publish'); ?></label>
	</td>
	</tr>
	
	<tr valign="top" id="twai_twap">
		<td class="xyz_twap_pleft15"> <?php _e('Attach image to twitter post','twitter-auto-publish'); ?>
		</td>
		<td><select id="xyz_twap_twpost_image_permission" name="xyz_twap_twpost_image_permission">
				<option value="0"
				<?php  if($post_twitter_image_permission==0) echo 'selected';?>>
					<?php _e('No','twitter-auto-publish'); ?></option>
				<option value="1"
				<?php  if($post_twitter_image_permission==1) echo 'selected';?>><?php _e('Yes','twitter-auto-publish'); ?></option>
		</select>
		</td>
	</tr>
	
	<tr valign="top" id="twmf_twap">
		<td class="xyz_twap_pleft15"> <?php _e('Message format for posting','twitter-auto-publish'); ?><img src="<?php echo $heimg?>"
						onmouseover="detdisplay_twap('xyz_twap_informationdiv')" onmouseout="dethide_twap('xyz_twap_informationdiv')" style="width:13px;height:auto;">
						<div id="xyz_twap_informationdiv" class="xyz_twap_informationdiv"
							style="display: none; font-weight: normal;">
							{POST_TITLE} - <?php _e('Insert the title of your post.','twitter-auto-publish'); ?><br/>
							{PERMALINK} - <?php _e('Insert the URL where your post is displayed.','twitter-auto-publish'); ?><br/>
							{POST_EXCERPT} - <?php _e('Insert the excerpt of your post.','twitter-auto-publish'); ?><br/>
							{POST_CONTENT} - <?php _e('Insert the description of your post.','twitter-auto-publish'); ?><br/>
							{BLOG_TITLE} - <?php _e('Insert the name of your blog.','twitter-auto-publish'); ?><br/>
							{USER_NICENAME} - <?php _e('Insert the nicename of the author.','twitter-auto-publish'); ?><br/>
							{POST_ID} - <?php _e('Insert the ID of your post.','twitter-auto-publish'); ?><br/>
							{POST_PUBLISH_DATE} - <?php _e('Insert the publish date of your post.','twitter-auto-publish'); ?><br/>
							{USER_DISPLAY_NAME} - <?php _e('Insert the display name of the author.','twitter-auto-publish'); ?>
						</div></td>
	<td>
	<select name="xyz_twap_info" id="xyz_twap_info" onchange="xyz_twap_info_insert(this)">
		<option value ="0" selected="selected"> --<?php _e('Select','twitter-auto-publish'); ?>-- </option>
		<option value ="1">{POST_TITLE}  </option>
		<option value ="2">{PERMALINK} </option>
		<option value ="3">{POST_EXCERPT}  </option>
		<option value ="4">{POST_CONTENT}   </option>
		<option value ="5">{BLOG_TITLE}   </option>
		<option value ="6">{USER_NICENAME}   </option>
		<option value ="7">{POST_ID}   </option>
		<option value ="8">{POST_PUBLISH_DATE}   </option>
		<option value ="9">{USER_DISPLAY_NAME}   </option>
		</select> </td></tr>
		
		<tr id="twmftarea_twap"><td>&nbsp;</td><td>
		<textarea id="xyz_twap_twmessage"  name="xyz_twap_twmessage"><?php echo esc_textarea($messagetopost);?></textarea>
	</td></tr>
	
	</table>
	<?php }?>
	</td></tr>
	
	
</table>
<script type="text/javascript">

	var edit_flag="<?php echo $GLOBALS['edit_flag'];?>";
	if(edit_flag==1)
		load_edit_action();
	if(edit_flag!=1)
		load_create_action();
	function load_edit_action()
	{
		document.getElementById("xyz_twap_post").value=1;
		var xyz_twap_default_selection_edit="<?php echo esc_html(get_option('xyz_twap_default_selection_edit'));?>";
		if(xyz_twap_default_selection_edit=="")
			xyz_twap_default_selection_edit=0;
		if(xyz_twap_default_selection_edit==1 || xyz_twap_default_selection_edit==2)
			return;
		jQuery('#xyz_twap_twpost_permission_0').attr('checked',true);
		displaycheck_twap();


	}
	function load_create_action()
	{
		document.getElementById("xyz_twap_post").value=1;
		var xyz_twap_default_selection_create="<?php echo esc_html(get_option('xyz_twap_default_selection_create'));?>";
		if(xyz_twap_default_selection_create=="")
			xyz_twap_default_selection_create=0;
		if(xyz_twap_default_selection_create==1 ||xyz_twap_default_selection_create==2)
			return;
		jQuery('#xyz_twap_twpost_permission_0').attr('checked',true);
		displaycheck_twap();
	}
	function xyz_twap_info_insert(inf){
		
	    var e = document.getElementById("xyz_twap_info");
	    var ins_opt = e.options[e.selectedIndex].text;
	    if(ins_opt=="0")
	    	ins_opt="";
	    var str=jQuery("textarea#xyz_twap_twmessage").val()+ins_opt;
	    jQuery("textarea#xyz_twap_twmessage").val(str);
	    jQuery('#xyz_twap_info :eq(0)').prop('selected', true);
	    jQuery("textarea#xyz_twap_twmessage").focus();

	}
	jQuery("#xyz_twap_twpost_permission_no").click(function(){
		displaycheck_twap();
		XyzTwapToggleRadio(0,'xyz_twap_twpost_permission');
		
	});
	jQuery("#xyz_twap_twpost_permission_yes").click(function(){
		displaycheck_twap();
		XyzTwapToggleRadio(1,'xyz_twap_twpost_permission');
		
	});
	</script>
<?php 
}
?>