<?php

/**
 * A check for bad users.
 * https://gist.github.com/joshkoenig/dbb543c02198330cbf87
 */
function bad_users_check() {
  $result = bad_users_check_query();
  $res = array();
  if (!empty($result)) {
    foreach ($result as $name) {
      $res[] = t('User "@name" discovered.', array(
        '@name' => $name,
      ));
    }
  }
  if (!empty($res)) {
    return $res;
  }
}

function bad_users_check_query() {
  // Check against a list of reported users.
  $users = array(
    'configure',
    'drplsys',
    'drupaldev',
    'n0n0x',
    'system',
  );
  $result = db_query('SELECT uid, name FROM {users} WHERE name IN (:users)', array(
    ':users' => $users,
  ));
  $ret_val = array();
  while ($user = $result->fetchObject()) {
    $ret_val[$user->uid] = $user->name;
  }
  // Check for users created 44 years 10 months ago (actually created date is zero).
  $result_old = db_query('SELECT uid, name, created FROM {users} WHERE created = 0');
  $ret_val_old = array();
  foreach ($result_old as $user) {
    if ($user->uid != 0) {
      $ret_val_old[$user->uid] = $user->name;
    }
  }
  return ($ret_val + $ret_val_old);
}
