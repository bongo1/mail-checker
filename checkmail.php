<?php
/*
Copyright (C) 2012 Kasper F. Brandt

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

namespace PoiTech\CheckMail;

class SmtpException extends \Exception
{
	public $Code;
	public $ErrorKind;
	public $Reply;

	public function __construct($code, $errorKind, $reply)
	{
		$this->Code = $code;
		$this->ErrorKind = $errorKind;
		$this->Reply = $reply;
	}
}

class MailChecker
{
	public static $PHPPath = 'php';
	public static $PythonPath = 'python';

	private $address;
	private $domain;
	private $local;
	public $Timeout;
	public $TestMail;
	public $TestHostname;
	public $AllowIntLocal; //allow international characters in local part (RFC 6530)

	private function IdnToAscii($s)
	{
		if (function_exists('idn_to_ascii'))
			return idn_to_ascii($s);
		return $this->IdnToAsciiPython($s);
		
	}

	private function IdnToAsciiPython($s)
	{
		$pythonPath = MailChecker::$PythonPath;
		$sesc = '';
		for ($i = 0; $i < strlen($s); $i++)
		{
			$c = $s[$i];
			if ($c == "\\")
				$sesc .= "\\\\";
			else if ($c == '"')
				$sesc .= '\\"';
			else if (ord($c) < 0x80 && ctype_print($c))
				$sesc .= $c;
			else
				$sesc .= '\\x'.sprintf('%02x', ord($c));
		}
		$prog = 'print(unicode("'.$sesc.'", "utf8").encode("idna"))';
		$command = escapeshellarg($pythonPath).' -c '.escapeshellarg($prog);
		ob_start();
		passthru($command);
		return trim(ob_get_clean());
	}

	private function ContainsIntChar($s)
	{
		return preg_match("/[\x80-\xFF]/s", $s) === 1;
	}

	public function __construct($address, $timeout = 10, $testmail = null, $testhostname = null, $encoding = 'utf8', $allowIntLocal = true)
	{
		$enc = str_replace(Array('-', '_'), '', strtolower($encoding));
		if ($enc != 'utf8')
		{
			if ($enc == 'latin1' || $enc == 'iso88591')
				$address = utf8_encode($address);
			else
				$address = iconv($encoding, 'utf8', $address);
		}
		$atpos = strpos($address, '@');
		if ($atpos === false)
		{
			$this->local = $address;
			$this->domain = '';
		}
		else
		{
			$this->local = substr($address, 0, $atpos);
			$this->domain = substr($address, $atpos+1);
		}

		if ($this->ContainsIntChar($this->domain))
		{
			//Domain part contains international characters
			$this->domain = $this->IdnToAscii($this->domain);
		}
		$this->address = $this->local . ($this->domain != '' ? '@'.$this->domain : '');
		$this->Timeout = $timeout;
		if ($testhostname == null)
			$testhostname = gethostname();
		if ($testmail == null)
			$testmail = "test@$testhostname";
		$this->TestMail = $testmail;
		$this->TestHostname = $testhostname;
		$this->AllowIntLocal = $allowIntLocal;
	}

	public function GetLocal()
	{
		return $this->local;
	}

	public function GetDomain()
	{
		return $this->domain;
	}

	public function GetAddress()
	{
		return $this->address;
	}

	public function FullValidate(&$realemail)
	{
		if (!$this->ValidateAddress())
			return 'InvalidAddress';
		if (!$this->MailExistsOnAny())
			return 'AddressNotFound';
		$realemail = substr($this->address, 0);
		return true;
	}

	public function ValidateAddress()
	{
		if ($this->AllowIntLocal)
		{
			//Replace international characters before validation
			//TODO: is there some unallowed unicode characters?
			$local = preg_replace('/[\x80-\xFF]/', 'x', $this->local);
		}
		else
			$local = $this->local;

		//Source: http://www.linuxjournal.com/article/9585?page=0,3		
		$domain = $this->domain;
		$localLen = strlen($local);
		$domainLen = strlen($domain);
		if ($localLen < 1 || $localLen > 64)
		{
		   // local part length exceeded
		   return false;
		}
		else if ($domainLen < 1 || $domainLen > 255)
		{
		   // domain part length exceeded
		   return false;
		}
		else if ($local[0] == '.' || $local[$localLen-1] == '.')
		{
		   // local part starts or ends with '.'
		   return false;
		}
		else if (preg_match('/\\.\\./', $local))
		{
		   // local part has two consecutive dots
		   return false;
		}
		else if (!preg_match('/^[A-Za-z0-9\\-\\.]+$/', $domain))
		{
		   // character not valid in domain part
		   return false;
		}
		else if (preg_match('/\\.\\./', $domain))
		{
		   // domain part has two consecutive dots
		   return false;
		}
		else if (!preg_match('/^(\\\\.|[A-Za-z0-9!#%&`_=\\/$\'*+?^{}|~.-])+$/',
		           str_replace("\\\\","",$local)))
		{
		   // character not valid in local part unless 
		   // local part is quoted
		   if (!preg_match('/^"(\\\\"|[^"])+"$/',
		       str_replace("\\\\","",$local)))
		   {
		      return false;
		   }
		}
		return true;
	}

	public function GetMXs()
	{
		$host = substr(strrchr($this->address, '@'), 1);
		$mxhosts = Array();
		$weight = Array();
		getmxrr($host, $mxhosts, $weight);
		if (empty($mxhosts) || $mxhosts[0] == null)
			return Array(Array(0, $host));
		$hosts = array_map(null, $weight, $mxhosts);
		usort($hosts, function ($a, $b) {return $a[0]-$b[0];});
		return $hosts;
	}

	private function GetReply($socket)
	{
		$buffer = '';
		$lastLine = false;
		while (!$lastLine)
		{
			$l = '';
			while (substr($l, -2) !== "\r\n")
			{
				$l .= fgets($socket, 1024);
				if (feof($socket))
					return Array(-1, $buffer.$l);
				if (strlen($l) > 1024)
					return Array(-2, $buffer.$l);
			}
			if (strlen($l) < 6)
				return Array(-3, $buffer.$l);
			if ($l[3] === ' ')
				$lastLine = true;
			else if ($l[3] !== '-')
				return Array(-3, $buffer.$l);
			$code = substr($l, 0, 3);
			if ((int)$code.'' !== $code)
				return Array(-3, $buffer.$l);

			$buffer .= $l;
		}
		return Array((int)$code, $buffer);
	}

	private function Cmd($socket, $cmd, $code)
	{
		if (fwrite($socket, "$cmd\r\n") !== strlen($cmd)+2)
			throw new SmtpException($code, 'ConnectionLost', null);
		$reply = $this->GetReply($socket);
		if ($reply[0] >= 200 && $reply[0] < 300)
			return true;
		if ($reply[0] == -1)
			throw new SmtpException($code, 'ConnectionLost', null);
		if ($reply[0] == -2)
			throw new SmtpException($code, 'ReplyTooLong', null);
		if ($reply[0] == -3)
			throw new SmtpException($code, 'InvalidReply', $reply[1]);
		if (($reply[0] >= 500 && $reply[0] <= 504) || $reply[0] == 554)
			throw new SmtpException($code, 'ServerError', $reply[1]);
		if ($reply[0] >= 500 && $reply[0] < 600)
			throw new SmtpException($code, 'PermanentError', $reply[1]);
		if ($reply[0] >= 400 && $reply[0] < 500)
			throw new SmtpException($code, 'TemporaryError', $reply[1]);
		throw new SmtpException($code, 'UnknownReply', $reply[1]);
	}

	public function MailExists($host)
	{
		$socket = @fsockopen($host, 25, $errno, $errstr, $this->Timeout);
		if (!$socket)
			return Array('ConnError', $errno, $errstr);

		try
		{
			$this->Cmd($socket, 'HELO '.$this->TestHostname, 'Helo');
			$this->Cmd($socket, "MAIL FROM:<{$this->TestMail}>", 'From');
			$this->Cmd($socket, "RCPT TO:<{$this->address}>", 'To');
			$this->Cmd($socket, 'QUIT', 'Quit');
		}
		catch (SmtpException $e)
		{
			try
			{
				if ($e->Code != 'Quit')
					$this->Cmd($socket, 'QUIT', 'Quit');
			}
			catch (\Exception $e) { }
			fclose($socket);
			return Array('SmtpError', $e->Code, $e->ErrorKind, $e->Reply);
		}
		return true;
	}

	private function ErrorClass($result)
	{
		if ($result === true)
			return 0;
		else if ($result[0] == 'SmtpError' && $result[1] == 'To' && $result[2] == 'PermanentError')
			return 2;
		else
			return 1;
	}

	private function RunChildFork($host)
	{
		$pid = pcntl_fork();
		if ($pid !== 0)
			return $pid;
		//ob_start();//prevent output to main process 
		register_shutdown_function(create_function('$pars', /*'ob_end_clean();*/'posix_kill(getmypid(), SIGKILL);'), array());//to kill self before exit();, or else the resource shared with parent will be closed
		$result = $this->MailExists($host);
		exit($this->ErrorClass($result));
	}

	private function WaitChildFork($pid, $nohang)
	{
		if ($nohang)
			pcntl_wait($status, WNOHANG);
		else
			pcntl_wait($status);
		return $status;
	}

	private function RunChildPopen($host)
	{
		$phppath = MailChecker::$PHPPath;
		$fileesc = str_replace(Array('\\', "'"), Array('\\\\', "\\'"), __FILE__);
		$hostesc = str_replace(Array('\\', "'"), Array('\\\\', "\\'"), $host);
		$addresc = str_replace(Array('\\', "'"), Array('\\\\', "\\'"), $this->address);
		$php = "
			include '$fileesc';
			\$checker = new ".__NAMESPACE__."\\MailChecker('$addresc');
			\$r = \$checker->MailExists('$hostesc');
			echo serialize(\$r);";
		$command = escapeshellarg($phppath).' -r '.escapeshellarg($php).' 2>&1';
		return popen($command, 'r');
	}

	private function WaitChildPopen($pipe, $nohang)
	{
		if ($nohang)
		{
			pclose($pipe);
			return null;
		}
		$d = fread($pipe, 102400);
		$r = unserialize($d);
		pclose($pipe);
		return $this->ErrorClass($r);
	}

	private function RunChild($host)
	{
		return $this->RunChildPopen($host);
	}

	private function WaitChild($c, $nohang = false)
	{
		return $this->WaitChildPopen($c, $nohang);
	}

	public function MailExistsOnAny()
	{
		$MXs = $this->GetMXs();
		$pids = Array();
		$childFailed = false;
		foreach ($MXs as $mx)
		{
			$pid = $this->RunChild($mx[1]);
			if ($pid === -1)
			{
				$childFailed = true;
				break;
			}
			$pids[] = $pid;
		}
		$stat = 1;
		foreach ($pids as $pid)
		{
			$status = $this->WaitChild($pid, $stat != 1);
			if ($stat == 1 && $status != 1)
				$stat = $status;
		}
		return $stat === 0;
	}
}

?>
