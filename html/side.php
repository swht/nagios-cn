<?php
include_once(dirname(__FILE__).'/includes/utils.inc.php');

$this_version = '4.3.2';
$link_target = 'main';
?>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">

<html>

<head>
<meta name="ROBOTS" content="NOINDEX, NOFOLLOW">
<title>Nagios Core</title>
<link href="stylesheets/common.css?<?php echo $this_version; ?>" type="text/css" rel="stylesheet">
</head>


<body class='navbar'>

<div class="navbarlogo">
	<a href="https://www.nagios.org" target="_blank"><img src="images/sblogo.png" height="39" width="140" border="0" alt="Nagios" /></a>
</div>

<div class="navsection">
	<div class="navsectiontitle">����</div>
	<div class="navsectionlinks">
		<ul class="navsectionlinks">
			<li><a href="main.php" target="<?php echo $link_target;?>">��ҳ</a></li>
			<li><a href="docs/" target="<?php echo $link_target;?>">�ĵ�(Ӣ��)</a></li>
			<li><a href="Nagios-cn.html" target="<?php echo $link_target;?>">����˵���ĵ�</a></li>
		</ul>
	</div>
</div>

<div class="navsection">
	<div class="navsectiontitle">��ǰ״̬</div>
	<div class="navsectionlinks">
		<ul class="navsectionlinks">
			<li><a href="<?php echo $cfg["cgi_base_url"];?>/tac.cgi" target="<?php echo $link_target;?>">����</a></li>
			<li>
				<a href="map.php?host=all" target="<?php echo $link_target;?>">����ͼ</a>
				<a href="<?php echo $cfg["cgi_base_url"];?>/statusmap.cgi?host=all" target="<?php echo $link_target;?>">(Legacy)</a>
			</li>
			<li><a href="<?php echo $cfg["cgi_base_url"];?>/status.cgi?hostgroup=all&amp;style=hostdetail" target="<?php echo $link_target;?>">����</a></li>
			<li><a href="<?php echo $cfg["cgi_base_url"];?>/status.cgi?host=all" target="<?php echo $link_target;?>">����</a></li>
			<li>
				<a href="<?php echo $cfg["cgi_base_url"];?>/status.cgi?hostgroup=all&amp;style=overview" target="<?php echo $link_target;?>">������</a>
				<ul>
					<li><a href="<?php echo $cfg["cgi_base_url"];?>/status.cgi?hostgroup=all&amp;style=summary" target="<?php echo $link_target;?>">����</a></li>
					<li><a href="<?php echo $cfg["cgi_base_url"];?>/status.cgi?hostgroup=all&amp;style=grid" target="<?php echo $link_target;?>">���</a></li>
				</ul>
			</li>
			<li>
				<a href="<?php echo $cfg["cgi_base_url"];?>/status.cgi?servicegroup=all&amp;style=overview" target="<?php echo $link_target;?>">������</a>
				<ul>
					<li><a href="<?php echo $cfg["cgi_base_url"];?>/status.cgi?servicegroup=all&amp;style=summary" target="<?php echo $link_target;?>">����</a></li>
					<li><a href="<?php echo $cfg["cgi_base_url"];?>/status.cgi?servicegroup=all&amp;style=grid" target="<?php echo $link_target;?>">���</a></li>
				</ul>
			</li>
		</ul>
	</div>
	<div class="navsectionheader">
		<ul>
			<li>�������
				<ul>
					<li><a href="<?php echo $cfg["cgi_base_url"];?>/status.cgi?host=all&amp;servicestatustypes=28" target="<?php echo $link_target;?>">����</a> (<a href="<?php echo $cfg["cgi_base_url"];?>/status.cgi?host=all&amp;type=detail&amp;hoststatustypes=3&amp;serviceprops=10&amp;servicestatustypes=28" target="<?php echo $link_target;?>">δ����</a>)</li>
					<li><a href="<?php echo $cfg["cgi_base_url"];?>/status.cgi?hostgroup=all&amp;style=hostdetail&amp;hoststatustypes=12" target="<?php echo $link_target;?>">����</a> (<a href="<?php echo $cfg["cgi_base_url"];?>/status.cgi?hostgroup=all&amp;style=hostdetail&amp;hoststatustypes=12&amp;hostprops=42" target="<?php echo $link_target;?>">δ����</a>)</li>
					<li><a href="<?php echo $cfg["cgi_base_url"];?>/outages.cgi" target="<?php echo $link_target;?>">��������</a></li>
				</ul>
			</li>
		</ul>
	</div>
	<div class="navbarsearch">
		<form method="get" action="<?php echo $cfg["cgi_base_url"];?>/status.cgi" target="<?php echo $link_target;?>">
			<fieldset>
				<legend>���ٲ��ң�</legend>
				<input type='hidden' name='navbarsearch' value='1'>
				<input type='text' name='host' size='15' class="NavBarSearchItem">
			</fieldset>
		</form>
	</div>
</div>

<div class="navsection">
	<div class="navsectiontitle">����</div>
	<div class="navsectionlinks">
		<ul class="navsectionlinks">
			<li><a href="<?php echo $cfg["cgi_base_url"];?>/avail.cgi" target="<?php echo $link_target;?>">������</a></li>
			<li>
				<a href="trends.html" target="<?php echo $link_target;?>">����</a>
				<a href="<?php echo $cfg["cgi_base_url"];?>/trends.cgi" target="<?php echo $link_target;?>">(Legacy)</a>
			</li>
			<li><a href="<?php echo $cfg["cgi_base_url"];?>/history.cgi?host=all" target="<?php echo $link_target;?>">����</a>
			<ul>
				<li><a href="<?php echo $cfg["cgi_base_url"];?>/history.cgi?host=all" target="<?php echo $link_target;?>">��ʷ</a></li>
				<li><a href="<?php echo $cfg["cgi_base_url"];?>/summary.cgi" target="<?php echo $link_target;?>">����</a></li>
				<li>
					<a href="histogram.html" target="<?php echo $link_target;?>">��ʷͼ</a>
					<a href="<?php echo $cfg["cgi_base_url"];?>/histogram.cgi" target="<?php echo $link_target;?>">(Legacy)</a>
				</li>
			</ul>
			</li>
			<li><a href="<?php echo $cfg["cgi_base_url"];?>/notifications.cgi?contact=all" target="<?php echo $link_target;?>">֪ͨ</a></li>
			<li><a href="<?php echo $cfg["cgi_base_url"];?>/showlog.cgi" target="<?php echo $link_target;?>">�¼���־</a></li>
		</ul>
	</div>
</div>

<div class="navsection">
	<div class="navsectiontitle">ϵͳ</div>
	<div class="navsectionlinks">
		<ul class="navsectionlinks">
			<li><a href="<?php echo $cfg["cgi_base_url"];?>/extinfo.cgi?type=3" target="<?php echo $link_target;?>">ע��</a></li>
			<li><a href="<?php echo $cfg["cgi_base_url"];?>/extinfo.cgi?type=6" target="<?php echo $link_target;?>">ͣ���ƻ�</a></li>
			<li><a href="<?php echo $cfg["cgi_base_url"];?>/extinfo.cgi?type=0" target="<?php echo $link_target;?>">������Ϣ</a></li>
			<li><a href="<?php echo $cfg["cgi_base_url"];?>/extinfo.cgi?type=4" target="<?php echo $link_target;?>">������Ϣ</a></li>
			<li><a href="<?php echo $cfg["cgi_base_url"];?>/extinfo.cgi?type=7" target="<?php echo $link_target;?>">��ʱ��ѯ</a></li>
			<li><a href="<?php echo $cfg["cgi_base_url"];?>/config.cgi" target="<?php echo $link_target;?>">����</a></li>
		</ul>
	</div>
</div>

</body>
</html>
