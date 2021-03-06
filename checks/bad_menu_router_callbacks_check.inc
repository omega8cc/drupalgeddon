<?php
/**
 * @file
 * Check for malicious menu_router callbacks.
 */

/**
 * Check for menu_router attacks with malicious callbacks.
 * @link https://gist.github.com/joshkoenig/70ebb6af239dd95f3ce6
 */
function bad_menu_router_callbacks_check() {
  $bad_callbacks = array(
    'php_eval',
    'assert',
    'exec',
    'passthru',
    'system',
    'shell_exec',
    'popen',
    'proc_open',
    'pcntl_exec',
    'eval',
    'preg_replace',
    'create_function',
    'include',
    'include_once',
    'require',
    'require_once',
    'ob_start',
    'array_diff_uassoc',
    'array_diff_ukey',
    'array_filter',
    'array_intersect_uassoc',
    'array_intersect_ukey',
    'array_map',
    'array_reduce',
    'array_udiff_assoc',
    'array_udiff_uassoc',
    'array_udiff',
    'array_uintersect_assoc',
    'array_uintersect_uassoc',
    'array_uintersect',
    'array_walk_recursive',
    'array_walk',
    'assert_options',
    'uasort',
    'uksort',
    'usort',
    'preg_replace_callback',
    'spl_autoload_register',
    'iterator_apply',
    'call_user_func',
    'call_user_func_array',
    'register_shutdown_function',
    'register_tick_function',
    'set_error_handler',
    'set_exception_handler',
    'session_set_save_handler',
    'sqlite_create_aggregate',
    'sqlite_create_function',
    'phpinfo',
    'posix_mkfifo',
    'posix_getlogin',
    'posix_ttyname',
    'getenv',
    'get_current_user',
    'proc_get_status',
    'get_cfg_var',
    'disk_free_space',
    'disk_total_space',
    'diskfreespace',
    'getcwd',
    'getlastmo',
    'getmygid',
    'getmyinode',
    'getmypid',
    'getmyuid',
    'echo',
    'print',
    'extract',
    'parse_str',
    'putenv',
    'ini_set',
    'mail',
    'header',
    'proc_nice',
    'proc_terminate',
    'proc_close',
    'pfsockopen',
    'fsockopen',
    'apache_child_terminate',
    'posix_kill',
    'posix_mkfifo',
    'posix_setpgid',
    'posix_setsid',
    'posix_setuid',
    'fopen',
    'tmpfile',
    'bzopen',
    'gzopen',
    'SplFileObject->__construct',
    'chgrp',
    'chmod',
    'chown',
    'copy',
    'file_put_contents',
    'lchgrp',
    'lchown',
    'link',
    'mkdir',
    'move_uploaded_file',
    'rename',
    'rmdir',
    'symlink',
    'tempnam',
    'touch',
    'unlink',
    'imagepng',
    'imagewbmp',
    'image2wbmp',
    'imagejpeg',
    'imagexbm',
    'imagegif',
    'imagegd',
    'imagegd2',
    'iptcembed',
    'ftp_get',
    'ftp_nb_get',
    'file_exists',
    'file_get_contents',
    'file',
    'fileatime',
    'filectime',
    'filegroup',
    'fileinode',
    'filemtime',
    'fileowner',
    'fileperms',
    'filesize',
    'filetype',
    'glob',
    'is_dir',
    'is_executable',
    'is_file',
    'is_link',
    'is_readable',
    'is_uploaded_file',
    'is_writable',
    'is_writeable',
    'linkinfo',
    'lstat',
    'parse_ini_file',
    'pathinfo',
    'readfile',
    'readlink',
    'realpath',
    'stat',
    'gzfile',
    'readgzfile',
    'getimagesize',
    'imagecreatefromgif',
    'imagecreatefromjpeg',
    'imagecreatefrompng',
    'imagecreatefromwbmp',
    'imagecreatefromxbm',
    'imagecreatefromxpm',
    'ftp_put',
    'ftp_nb_put',
    'exif_read_data',
    'read_exif_data',
    'exif_thumbnail',
    'exif_imagetype',
    'hash_file',
    'hash_hmac_file',
    'hash_update_file',
    'md5_file',
    'sha1_file',
    'highlight_file',
    'show_source',
    'php_strip_whitespace',
    'get_meta_tags',
    'ctools_access_menu',
  );

  $res = array();

  $sql = <<<sql
SELECT mr.path,
       mr.access_arguments,
       mr.page_arguments,
       mr.theme_arguments,
       mr.title_arguments
FROM {menu_router} mr
WHERE mr.access_callback = :cb
   OR mr.delivery_callback = :cb
   OR mr.page_callback = :cb
   OR mr.theme_callback = :cb
   OR mr.title_callback = :cb
sql;

  foreach ($bad_callbacks as $bad_callback) {
    $result = db_query($sql, array(':cb' => $bad_callback));
    while ($router = $result->fetchAssoc()) {
      $t_args = array('@name' => $bad_callback, '@path' => $router['path']);
      // If this is for ctools_access_menu, confirm it is injecting PHP
      // Otherwise, just report the dangerous menu callback
      if ($bad_callback === 'ctools_access_menu') {
        // Scan each column for PHP
        foreach ($router as $key => $value) {
          if (stripos($value, 'php') !== FALSE) {
            $res[] = t('Menu router @name discovered at @path using PHP.', $t_args);
          }
        }
      }
      else {
        $res[] = t('Menu router @name discovered at @path.', $t_args);
      }
    }
  }

  return $res;
}
