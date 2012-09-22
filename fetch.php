#!/usr/bin/php
<?php
	require 'Snoopy.class.php';

	formalize(analyze(file_exists('whois.tmp') ? recovery() : fetch()));

	function fetch() {
		$root_db_url = 'http://www.iana.org/domains/root/db/';

		$root_db_url_len = strlen($root_db_url);

		$snoopy = new Snoopy;

		echo "Discovering TLDs, please wait ...";

		$snoopy->fetchlinks($root_db_url);

		$tlds = array();


		foreach($snoopy->results as $tld) {
			if(strpos($tld, $root_db_url) === false) { continue; }

			$tld = substr($tld, $root_db_url_len, strlen($tld) - $root_db_url_len - 5);

			echo  "TLD {$tld} detected. \n";

			$tlds[$tld] = false;
		}

		echo "Fetching whois data, please wait ... \n";

		$tld_c = count($tlds);
		$tld_i = 1;

		foreach($tlds as $tld=>$r) {
			echo "[{$tld_i}/{$tld_c}] Fetching TLD {$tld}, please wait ...";

			$tlds[$tld] = array();

			$tlds[$tld]['raw'] = shell_exec("whois -h whois.iana.org {$tld}");

			echo "OK \n";
			$tld_i++;
		}
		
		file_put_contents('whois.tmp', json_encode($tlds));

		return $tlds;
	}

	function recovery() {
		return json_decode(file_get_contents('whois.tmp'), true);
	}

	function analyze($tlds) {
		$tld_c = count($tlds);
		$tld_i = 1;

		echo "{$tld_c} TLDs found, start analyzing ... \n";

		foreach($tlds as $tld=>$data) {
			echo "[{$tld_i}/{$tld_c}] Analyzing TLD {$tld}, please wait ...";
			$tlds[$tld] = array_merge($data, _analyze_separate($data['raw']));
			echo "OK \n";
			$tld_i++;
		}

		file_put_contents('whois.result', json_encode($tlds));

		unlink('whois.tmp');

		return $tlds;
	}

	function _analyze_separate($data) {
		$data = explode("\n", $data);

		$data = array_filter($data, '_analyze_separate_filter');

		$return = array();

		foreach($data as $item) {
			if(($pos = strpos($item, ':')) !== false) {
				$key = trim(substr($item, 0, $pos));

				if(isset($return[$key])) {
					$return[$key] = array_merge( (
							is_array($return[$key]) ? $return[$key] : array($return[$key])
					), array(trim(substr($item, $pos + 1))));

				} else {
					$return[$key] = trim(substr($item, $pos + 1));
				}
			}
		}

		unset($data);

		return $return;
	}

	function _analyze_separate_filter($data) {
		$data = trim($data);

		if(strlen($data) == 0) {
			return false;
		}

		if($data{0} == '%') {
			return false;
		}

		return $data;
	}

	function formalize($data) {
		$tlds = array();
		$errs = 0;
		$ns = "";
		$whois = "";

		foreach($data as $tld=>$tld_config) {
			unset($tld_config['raw']);

			if(!isset($tld_config['nserver'])) {
				$errs++;

				echo "($errs) Warning: TLD {$tld} doesn't have a valid nameserver. \n";
			
				$tld_config['nserver'] = '';
			}

			if(is_string($tld_config['nserver'])) {
				$ns .= "\"{$tld}\": {$tld_config['nserver']}\n";
			} else {
				foreach($tld_config['nserver'] as $_ns) {
					$ns .= "\"{$tld}\": {$_ns}\n";

					unset($_ns);
				}
			}

			if(!isset($tld_config['whois'])) {
				$errs++;

				echo "($errs) Warning: TLD {$tld} doesn't have a valid whois server. \n";

				$tld_config['whois'] = '';

			}

			if(is_string($tld_config['whois'])) {
				$whois .= "\"{$tld}\": {$tld_config['whois']}\n";
			} else {
				foreach($tld_config['whois'] as $_whois) {
					$whois .= "\"{$tld}\": {$_whois}\n";

					unset($_whois);
				}
			}
		}

		file_put_contents('nameservers', $ns);
		file_put_contents('whois-servers', $whois);
	}
