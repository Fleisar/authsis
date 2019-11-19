<?php
	////////////////////
	// AUTH SIS v.1.2 //
	//----------------//
	// by Fleisar     //
	////////////////////
	// PROCCESS

	// ACTIONS
	// -- LOGIN / ENDED
	// -- REGISTER / ENDED
	// -- CHANGE PASSWORD / ENDED
	// -- CHANGE USERNAME / ENDED
	// -- SET PERMISSIONS / ENDED
	// -- ADD PERMISSIONS / ENDED
	// -- REMOVE PERMISSIONS / ENDED
	// -- CHANGE STATUS / ENDED

	// AUTH SIS - PERMISSIONS
	// -- authsis.personal.change.password
	// -- authsis.personal.change.username
	// -- authsis.permissions.set
	// -- authsis.permissions.add
	// -- authsis.permissions.remove
	// -- authsis.user.change.status

	// CONFIGS
	// MYSQL
	$authsis_config['mysqli']['ip'] = 'localhost';
	$authsis_config['mysqli']['port'] = 3306;
	$authsis_config['mysqli']['database'] = 'general';
	$authsis_config['mysqli']['user'] = 'root';
	$authsis_config['mysqli']['password'] = 'password';
	// AUTH SIS GENERAL
	$authsis_config['authsis']['table'] = 'authsis.auth';
	$authsis_config['authsis']['encrypt'] = true;
	//AUTH SIS DEFAULT VALUES
	$authsis_config['authsis']['defperms'] = '
		authsis.personal.change.password
		authsis.personal.change.username
	';

	$authsis_config['authsis']['chupdate'] = false;
	// CHECK STATIC VARIABLES
	if(!isset($_COOKIE['PHPSESSID'])){
		session_start();
	}
	// SET DYNAMIC VARIABLES
	$authsis_action = $_POST['action'];
	$authsis_login = $_POST['login'];
	$authsis_username = $_POST['username']; //use only when changing username
	if($authsis_config['authsis']['encrypt'] == true){
		$authsis_password = md5(md5($_POST['password']));
		$authsis_newpassword = md5(md5($_POST['newpassword']));
	}else{
		$authsis_password = $_POST['password'];
		$authsis_newpassword = $_POST['newpassword'];
	}
	$authsis_encsubmit = $_POST['encsubmit'];
	$authsis_session = $_COOKIE['PHPSESSID'];
	$authsis_permissions = $_POST['permissions'];
	$authsis_targetlogin = $_POST['targetlogin'];
	$authsis_status = $_POST['status'];
	$authsis_email = $_POST['email'];
	// INITIELIZATION MYSQLI & HIS TABLES
	if(!$authsis_mysqli =  new mysqli(
		$authsis_config['mysqli']['ip'],
		$authsis_config['mysqli']['user'],
		$authsis_config['mysqli']['password'],
		$authsis_config['mysqli']['database'],
		$authsis_config['mysqli']['port']
	)){
		authsis_fatal_authsis_error(1);
	}
	// CHECK TABLE
	if(!$authsis_mysqli->query("
		SELECT *
		FROM `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
	")){
		authsis_warning(0);
		if(!$authsis_mysqli->query("
			CREATE TABLE `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`(
				`id` int(11) NOT NULL PRIMARY KEY AUTO_INCREMENT,
				`status` int(11) NOT NULL DEFAULT '0',
				`login` text NOT NULL,
				`username` text NOT NULL,
				`password` text NOT NULL,
				`email` text NOT NULL,
				`permissions` text NOT NULL,
				`session` text,
				`last-online` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
				`registered` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
			)
		")){
			authsis_fatal_authsis_error(0);
		}
	}
	// CHECK SYSTEM ACCOUNT
	if($authsis_system_acc = $authsis_mysqli->query("
		SELECT *
		FROM `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
		WHERE `id`=1 AND `login`='system'
	")){
		if($authsis_system_acc->num_rows==0){
			authsis_error(0);
			if(!$authsis_mysqli->query("
				INSERT INTO `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
							(`login`,`username`,`password`,`email`,`permissions`)
							VALUES (
								'system',
								'SYSTEM',
								'1e2478275e4d4f3d88312d4b4ffd7c1c',
								'registrator@fle.su',
								'
									authsis.personal.change.password
									authsis.personal.change.username
									authsis.permissions.set
									authsis.permissions.add
									authsis.permissions.remove
									authsis.user.change.status
								'
							)
			")){
				authsis_fatal_authsis_error(2);
			}
		}
	}else{
		authsis_fatal_authsis_error(0);
	}
	// ACTIONS
	switch ($authsis_action){
		// LOGOUT
		// INPUT VAR ['$authsis_session']
		case 'logout':
			if($authsis_logout = $authsis_mysqli->query("
				SELECT *
				FROM `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
				WHERE `session`='".$authsis_mysqli->real_escape_string($authsis_session)."'
			")){
				if($authsis_logout->num_rows != 0){
					if($authsis_mysqli->query("
						UPDATE `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
						SET `session`='0'
						WHERE `session`='".$authsis_mysqli->real_escape_string($authsis_session)."'
					")){
						authsis_callback(0);
					}else{
						authsis_fatal_authsis_error(2);
					}
				}else{
					authsis_callback(7);
				}
			}else{
				authsis_fatal_authsis_error(0);
			}
		break;
		// LOGIN
		// INPUT VAR ['$authsis_login, $authsis_password, $authsis_session']
		case 'login':
			if(
				preg_match("/^[a-zA-Z0-9_-]{3,16}$/",$authsis_login) &&
				preg_match("/^[a-zA-Z0-9_-]{3,16}$/",$_POST['password'])
			){
				if($authsis_user = $authsis_mysqli->query("
					SELECT *
					FROM `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
					WHERE
						`login` = '".$authsis_mysqli->real_escape_string($authsis_login)."' AND
						`password` = '".$authsis_mysqli->real_escape_string($authsis_password)."'
				")){
					if($authsis_user->num_rows==1){
						if($authsis_mysqli->query("
							UPDATE `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
							SET `session` = '".$authsis_mysqli->real_escape_string($authsis_session)."'
							WHERE
								`login` = '".$authsis_mysqli->real_escape_string($authsis_login)."' AND
								`password` = '".$authsis_mysqli->real_escape_string($authsis_password)."'
						")){
							authsis_callback(0);
						}else{
							authsis_fatal_authsis_error(2);
						}
					}else{
						authsis_callback(2);
					}
				}else{
					authsis_fatal_authsis_error(1);
				}
			}else{
				authsis_callback(1);
			}
		break;
		// REGISTER
		// INPUT VAR ['$authsis_login, $authsis_password']
		case 'register':
			if($authsis_config['authsis']['encrypt'] != true && !isset($authsis_encsubmit)){
				authsis_callback(4);
			}
			if(
				preg_match("/^[a-zA-Z0-9_-]{3,16}$/",$authsis_login) &&
				preg_match("/^[a-zA-Z0-9_-]{3,16}$/",$_POST['password']) &&
                $authsis_email != ''
			){
				if($authsis_uses = $authsis_mysqli->query("
					SELECT *
					FROM `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
					WHERE `login` = '".$authsis_mysqli->real_escape_string($authsis_login)."'
				")){
					if($authsis_uses->num_rows==0){
						if($authsis_mysqli->query("
							INSERT INTO `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
							(`login`,`username`,`password`,`email`,`permissions`)
							VALUES (
								'".$authsis_mysqli->real_escape_string($authsis_login)."',
								'".$authsis_mysqli->real_escape_string($authsis_login)."',
								'".$authsis_mysqli->real_escape_string($authsis_password)."',
								'".$authsis_mysqli->real_escape_string($authsis_email)."',
								'".$authsis_mysqli->real_escape_string($authsis_config['authsis']['defperms'])."'
							)
						")){
							authsis_callback(0);
							system_message(0);
						}else{
							authsis_fatal_authsis_error(2);
						}
					}else{
						authsis_callback(3);
					}
				}else{
					authsis_fatal_authsis_error(0);
				}
			}else{
				authsis_callback(1);
			}
		break;
		// CHANGE PASSWORD
		// REQUIRE "authsis.personal.change.password"
		// INPUT VAR ['$authsis_login, $authsis_password, $authsis_newpassword']
		case 'change-password':
			if(
				preg_match("/^[a-zA-Z0-9_-]{3,16}$/",$authsis_login) &&
				preg_match("/^[a-zA-Z0-9_-]{3,16}$/",$_POST['password']) &&
				preg_match("/^[a-zA-Z0-9_-]{3,16}$/",$_POST['newpassword'])
			){
				if($authsis_user = $authsis_mysqli->query("
					SELECT *
					FROM `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
					WHERE
						`login` = '".$authsis_mysqli->real_escape_string($authsis_login)."' AND
						`password` = '".$authsis_mysqli->real_escape_string($authsis_password)."'
				")){
					if($authsis_user->num_rows!=0){
						$authsis_user = $authsis_user->fetch_assoc();
						if(strripos($authsis_user['permissions'], "authsis.personal.change.password")){
							if($authsis_mysqli->query("
								UPDATE `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
								SET `password` = '".$authsis_mysqli->real_escape_string($authsis_newpassword)."'
								WHERE
									`login` = '".$authsis_mysqli->real_escape_string($authsis_login)."' AND
									`password` = '".$authsis_mysqli->real_escape_string($authsis_password)."'
							")){
								authsis_callback(0);
							}else{
								authsis_fatal_authsis_error(2);
							}
						}else{
							authsis_callback(5);
						}
					}else{
						authsis_callback(2);
					}
				}else{
					authsis_fatal_authsis_error(0);
				}
			}else{
				authsis_callback(1);
			}
		break;
		// RESTORE PASSWORD
        // REQUIRE "authsis.personal.change.password"
        // INPUT VAR ['$authsis_email, $authsis_password']
        case 'restore-password':
            if(
                $authsis_email != '' &&
                $_POST['password'] != ''
            ){
                if($authsis_user = $authsis_mysqli->query("
                    SELECT *
                    FROM `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
                    WHERE
                        `email` = '".$authsis_mysqli->real_escape_string($authsis_email)."'
                ")){
                    if($authsis_user->num_rows != 0){
                        if($authsis_user = $authsis_mysqli->query("
                            UPDATE `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
                            SET `password` = '".$authsis_mysqli->real_escape_string($authsis_password)."'
                            WHERE
                                `email` = '".$authsis_mysqli->real_escape_string($authsis_email)."'
                        ")){
                            authsis_callback(0);
                        }else{
                            authsis_fatal_authsis_error(1);
                        }
                    }else{
                        authsis_callback(6);
                    }
                }else{
                    authsis_fatal_authsis_error(1);
                }
            }else{
                authsis_callback(1);
            }
        break;
		// CHANGE USERNAME
		// REQUIRE "authsis.personal.change.username"
		// INPUT VAR ['$authsis_login, $authsis_password, $authsis_username']
		case 'change-username':
			if(
				preg_match("/^[a-zA-Z0-9_-]{3,16}$/",$authsis_login) &&
				preg_match("/^[a-zA-Z0-9_-]{3,16}$/",$_POST['password']) &&
				preg_match("/^[a-zA-Z0-9_-]{3,16}$/",$authsis_username)
			){
				if($authsis_user = $authsis_mysqli->query("
					SELECT *
					FROM `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
					WHERE
						`login` = '".$authsis_mysqli->real_escape_string($authsis_login)."' AND
						`password` = '".$authsis_mysqli->real_escape_string($authsis_password)."'
				")){
					if($authsis_user->num_rows==1){
						$authsis_user = $authsis_user->fetch_assoc();
						if(strripos($authsis_user['permissions'], "authsis.personal.change.username")){
							if($authsis_mysqli->query("
								UPDATE `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
								SET `username` = '".$authsis_mysqli->real_escape_string($authsis_username)."'
								WHERE
									`login` = '".$authsis_mysqli->real_escape_string($authsis_login)."' AND
									`password` = '".$authsis_mysqli->real_escape_string($authsis_password)."'
							")){
								authsis_callback(0);
							}else{
								authsis_fatal_authsis_error(2);
							}
						}else{
							authsis_callback(5);
						}
					}else{
						authsis_callback(2);
					}
				}else{
					authsis_fatal_authsis_error(1);
				}
			}else{
				authsis_callback(1);
			}
		break;
		// SET PERMISSIONS
		// REQUIRE "authsis.permissions.set"
		// INPUT VAR ['$authsis_login, $authsis_password, $authsis_targetlogin, $authsis_permissions']
		case 'permission-set':
			if(
				preg_match("/^[a-zA-Z0-9_-]{3,16}$/",$authsis_login) &&
				preg_match("/^[a-zA-Z0-9_-]{3,16}$/",$_POST['password']) &&
				preg_match("/^[a-zA-Z0-9_-]{3,16}$/",$authsis_targetlogin)
			){
				if($authsis_user = $authsis_mysqli->query("
					SELECT *
					FROM `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
					WHERE
						`login` = '".$authsis_mysqli->real_escape_string($authsis_login)."' AND
						`password` = '".$authsis_mysqli->real_escape_string($authsis_password)."'
				")){
					if($authsis_user->num_rows==1){
						$authsis_user = $authsis_user->fetch_assoc();
						if(strripos($authsis_user['permissions'], "authsis.permissions.set")){
							if($authsis_target = $authsis_mysqli->query("
								SELECT *
								FROM `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
								WHERE `login`='".$authsis_mysqli->real_escape_string($authsis_targetlogin)."'
							")){
								if($authsis_target->num_rows!=0){
									if($authsis_mysqli->query("
										UPDATE `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
										SET `permissions` = '".$authsis_mysqli->real_escape_string($authsis_permissions)."'
										WHERE `login` = '".$authsis_mysqli->real_escape_string($authsis_targetlogin)."'
									")){
										authsis_callback(0);
									}else{
										authsis_fatal_authsis_error(2);
									}
								}else{
									authsis_callback(6);
								}
							}else{
								authsis_fatal_authsis_error(2);
							}
						}else{
							authsis_callback(5);
						}
					}else{
						authsis_callback(2);
					}
				}else{
					authsis_fatal_authsis_error(1);
				}
			}else{
				authsis_callback(1);
			}
		break;
		// ADD PERMISSIONS
		// REQUIRE "authsis.permissions.add"
		// INPUT VAR ['$authsis_login, $authsis_password, $authsis_targetlogin, $authsis_permissions']
		case 'permission-add':
			if(
				preg_match("/^[a-zA-Z0-9_-]{3,16}$/",$authsis_login) &&
				preg_match("/^[a-zA-Z0-9_-]{3,16}$/",$_POST['password']) &&
				preg_match("/^[a-zA-Z0-9_-]{3,16}$/",$authsis_targetlogin)
			){
				if($authsis_user = $authsis_mysqli->query("
					SELECT *
					FROM `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
					WHERE
						`login` = '".$authsis_mysqli->real_escape_string($authsis_login)."' AND
						`password` = '".$authsis_mysqli->real_escape_string($authsis_password)."'
				")){
					if($authsis_user->num_rows==1){
						$authsis_user = $authsis_user->fetch_assoc();
						if(strripos($authsis_user['permissions'], "authsis.permissions.add")){
							if($authsis_target = $authsis_mysqli->query("
								SELECT *
								FROM `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
								WHERE `login`='".$authsis_mysqli->real_escape_string($authsis_targetlogin)."'
							")){
								if($authsis_target->num_rows!=0){
									$authsis_target = $authsis_target->fetch_assoc();
									$authsis_perms = $authsis_target['permissions'].' '.$authsis_permissions;
									if($authsis_mysqli->query("
										UPDATE `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
										SET `permissions` = '".$authsis_mysqli->real_escape_string($authsis_perms)."'
										WHERE `login` = '".$authsis_mysqli->real_escape_string($authsis_targetlogin)."'
									")){
										authsis_callback(0);
									}else{
										authsis_fatal_authsis_error(2);
									}
								}else{
									authsis_callback(6);
								}
							}else{
								authsis_fatal_authsis_error(2);
							}
						}else{
							authsis_callback(5);
						}
					}else{
						authsis_callback(2);
					}
				}else{
					authsis_fatal_authsis_error(1);
				}
			}else{
				authsis_callback(1);
			}
		break;
		// REMOVE PERMISSIONS
		// REQUIRE "authsis.permissions.remove"
		// INPUT VAR ['$authsis_login, $authsis_password, $authsis_targetlogin, $authsis_permissions']
		case 'permission-remove':
			if(
				preg_match("/^[a-zA-Z0-9_-]{3,16}$/",$authsis_login) &&
				preg_match("/^[a-zA-Z0-9_-]{3,16}$/",$_POST['password']) &&
				preg_match("/^[a-zA-Z0-9_-]{3,16}$/",$authsis_targetlogin)
			){
				if($authsis_user = $authsis_mysqli->query("
					SELECT *
					FROM `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
					WHERE
						`login` = '".$authsis_mysqli->real_escape_string($authsis_login)."' AND
						`password` = '".$authsis_mysqli->real_escape_string($authsis_password)."'
				")){
					if($authsis_user->num_rows==1){
						$authsis_user = $authsis_user->fetch_assoc();
						if(strripos($authsis_user['permissions'], "authsis.permissions.remove")){
							if($authsis_target = $authsis_mysqli->query("
								SELECT *
								FROM `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
								WHERE `login`='".$authsis_mysqli->real_escape_string($authsis_targetlogin)."'
							")){
								if($authsis_target->num_rows!=0){
									$authsis_target = $authsis_target->fetch_assoc();
									$authsis_permission = explode(" ", $authsis_permissions);
									$authsis_perms = substr(
										$authsis_target['permissions'],
										strripos($authsis_target['permissions'], $authsis_permission),
										strlen($authsis_permission)
									);
									if($authsis_mysqli->query("
										UPDATE `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
										SET `permissions` = '".$authsis_mysqli->real_escape_string($authsis_perms)."'
										WHERE `login` = '".$authsis_mysqli->real_escape_string($authsis_targetlogin)."'
									")){
										authsis_callback(0);
									}else{
										authsis_fatal_authsis_error(2);
									}
								}else{
									authsis_callback(6);
								}
							}else{
								authsis_fatal_authsis_error(2);
							}
						}else{
							authsis_callback(5);
						}
					}else{
						authsis_callback(2);
					}
				}else{
					authsis_fatal_authsis_error(1);
				}
			}else{
				authsis_callback(1);
			}
		break;
		case 'change-status':
			// target login, from login, from password and status
			if(
				preg_match("/^[a-zA-Z0-9_-]{3,16}$/",$authsis_login) &&
				preg_match("/^[a-zA-Z0-9_-]{3,16}$/",$_POST['password']) &&
				preg_match("/^[a-zA-Z0-9_-]{3,16}$/",$authsis_targetlogin)
			){
				if($authsis_user = $authsis_mysqli->query("
					SELECT *
					FROM `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
					WHERE
						`login` = '".$authsis_mysqli->real_escape_string($authsis_login)."' AND
						`password` = '".$authsis_mysqli->real_escape_string($authsis_password)."'
				")){
					if($authsis_user->num_rows==1){
						$authsis_user = $authsis_user->fetch_assoc();
						if(strripos($authsis_user['permissions'], "authsis.user.change.status")){
							if($authsis_target = $authsis_mysqli->query("
								SELECT *
								FROM `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
								WHERE `login`='".$authsis_mysqli->real_escape_string($authsis_targetlogin)."'
							")){
								if($authsis_target->num_rows!=0){
									if($authsis_mysqli->query("
										UPDATE `".$authsis_mysqli->real_escape_string($authsis_config['authsis']['table'])."`
										SET `status` = '".$authsis_mysqli->real_escape_string($authsis_status)."'
										WHERE `login` = '".$authsis_mysqli->real_escape_string($authsis_targetlogin)."'
									")){
										authsis_callback(0);
									}else{
										authsis_fatal_authsis_error(2);
									}
								}else{
									authsis_callback(6);
								}
							}else{
								authsis_fatal_authsis_error(2);
							}
						}else{
							authsis_callback(5);
						}
					}else{
						authsis_callback(2);
					}
				}else{
					authsis_fatal_authsis_error(1);
				}
			}else{
				authsis_callback(1);
			}
		break;
	}
	// GLOBAL FUNCTIONS
	function authsis_getUser($authsis_tlogin){
		if($authsis_tlogin != ''){
			if($authsis_user = $GLOBALS['authsis_mysqli']->query("
				SELECT `status`,`login`,`username`,`permissions`,`session`,`last-online`,`registered`
				FROM `".$GLOBALS['config']['authsis']['table']."`
				WHERE `login`='".$GLOBALS['authsis_mysqli']->real_escape_string($authsis_tlogin)."'
			")){
				return $authsis_user->fetch_assoc();
			}else{
				return false;
			}
		}else{
			if($authsis_user = $GLOBALS['authsis_mysqli']->query("
				SELECT *
				FROM `".$GLOBALS['authsis_config']['authsis']['table']."`
				WHERE `session`='".$GLOBALS['authsis_mysqli']->real_escape_string($GLOBALS['authsis_session'])."'
			")){
				return $authsis_user->fetch_assoc();
			}else{
				return false;
			}
		}
	}

	// authsis_callback
	// 0 - OK
	// 1 - login or password doesn't match
	// 2 - failed to find user (authorization failed)
	// 3 - that login already uses
	// 4 - submit that your password will not be encrypted
	// 5 - no permissions
	// 6 - target not found
	// 7 - already logout
	// -- SYSTEM MESSAGES
	// 0 - password doesn't encrypt
	function authsis_callback($authsis_code){
		echo "<authsis_callback>".$authsis_code."</authsis_callback>";
		exit;
	}
	function system_message($authsis_code){
		switch ($authsis_code){
			case '0':
				echo "<script>alert('')</script>";
			break;
		}
		exit;
	}
	// authsis_errorS
	// -- FATAL authsis_errorS
	// 0 - authsis_error while sql query
	// 1 - authsis_error while connecting with sql
	// 2 - unknown authsis_error
	// -- DEFAULT authsis_errorS
	// 0 - sys account not found
	// -- authsis_warning MESSAGES
	// 0 - auth table not found
	function authsis_fatal_authsis_error($authsis_code){
		switch ($authsis_code){
			case '0':
				echo "['AUTH SIS']['FATAL authsis_error']: Unknown authsis_error while sql query.";
			break;
			case '1':
				echo "['AUTH SIS']['FATAL authsis_error']: Unable connect to sql server.";
			break;
			case '2':
				echo "['AUTH SIS']['WTF authsis_error']: I don't know how, but you break me. (@_@) aww~~";
			break;
		}
		exit;
	}
	function authsis_error($authsis_code){
		switch ($authsis_code){
			case '0':
				echo "['AUTH SIS']['authsis_error']: System account not found.";
			break;
		}
	}
	function authsis_warning($authsis_code){
		switch ($authsis_code){
			case '0':
				echo "['AUTH SIS']['authsis_warning']: Authorization table not found. Creating new table...";
		}
	}
?>