<?php

/**
 * A check for bad files.
 * https://www.drupal.org/node/2360269
 *
 * WTF people. Why can your webserver even write to your codebase?
 */
function suspicious_files_check() {
  $result = suspicious_files_check_query();
  $res = array();
  if (!empty($result)) {
    foreach ($result as $file) {
      $res[] = t('Suspicious file "@file" discovered.', array(
        '@file' => $file,
      ));
    }
  }
  if (!empty($res)) {
    return $res;
  }
}

function suspicious_files_check_query() {
  $found_files = file_scan_directory('.', '#.*\.php#', array('callback' => '_suspicious_files_callback_sites'));
  // glob(DRUPAL_ROOT . '/*/*/*.php');
  foreach ($found_files as $found_file) {
    if (!preg_match('#/(sites|profiles)/#', $found_file->uri)) {
      $files[] = realpath(DRUPAL_ROOT . DIRECTORY_SEPARATOR . $found_file->uri);
    }
  }

  $known_files = _suspicious_files_whitelist();
  foreach ($files as $file) {
    if (is_array($known_files) && !in_array($file, $known_files)) {
      // Exceptions to avoid too many false positives.
      if (stristr($file, '/sites/') === FALSE &&                    // Too many false positives.
          stristr($file, '/data/all/') === FALSE &&                 // Valid BOA path.
          stristr($file, '/data/disk/all/') === FALSE &&            // Valid BOA path.
          stristr($file, '/drushrc.php') === FALSE &&               // Valid Drush file.
          stristr($file, '/js.php') === FALSE &&                    // Valid BOA file/symlink.
          stristr($file, '/local.settings.php') === FALSE &&        // Valid Aegir file.
          stristr($file, '/modules/o_contrib_seven/') === FALSE &&  // Valid BOA path.
          stristr($file, '/rtoc.php') === FALSE &&                  // Valid BOA file.
          stristr($file, '/solr.php') === FALSE &&                  // Valid BOA file.
          stristr($file, '/themes/rubik/') === FALSE &&             // Valid BOA path.
          stristr($file, '/themes/tao/') === FALSE &&               // Valid BOA path.
          stristr($file, '/FirePHPCore/') === FALSE) {              // Whitelist FirePHPCore.
        $return[] = $file;
      }
    }
  }
  if (!empty($return)) {
    return $return;
  }
}

/**
 * List of files in a clean Drupal 7.33 install.
 */
function _suspicious_files_whitelist() {
  // Use correct hash for latest core (note: tree hash, not commit hash) from:
  // http://cgit.drupalcode.org/drupal/commit/?id=4ba5f184c69306da0e30260890f01ea0694af274
  $tree_list_url = 'https://github.com/drupal/drupal/tree-list/a27ea4ac2112bc9c70e5cf989b87b545ef501813';

  $extra_whitelist = array(
    'modules/help/help.api.php', // A file removed with Drupal 7.29
    'themes/tests/test_theme/template.php', // Legacy test_theme
  );
  if ($response = drupal_http_request($tree_list_url)) {
    if ($json = json_decode($response->data)) {
      foreach ($json->paths as $path) {
        $paths[] = realpath(DRUPAL_ROOT . '/' . $path);
      }

      foreach ($extra_whitelist as $path) {
        $paths[] = realpath(DRUPAL_ROOT . '/' . $path);
      }

      return $paths;
    }
  }
}

/**
 * Callback to exclude sites/*.
 */
function _suspicious_files_callback_sites($file) {
  if (!preg_match('#./sites#', $file)) {
    return $file;
  }
}
