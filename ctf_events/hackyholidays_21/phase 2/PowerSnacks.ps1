# 1
$answer = For ($i=1; $i -le 1337; $i++) {
	if ($i % 42 -eq 0){
		Write-Output("Life, the universe, and everything")
	}else{
		Write-Output($i)
	}
}
$answer | check


# 2
$answer = ForEach($word In $(Get-Content ./dictionary | Sort-Object  {$_.Length}, {$_.ToString()})) {
	 if($word.Length -gt 1){
		$scrabble_chars = "iydhlao"
		$match = 1
		ForEach($char in $word.ToCharArray()){
			if(!($scrabble_chars.Contains($char))){
				$match = 0
			}
			$scrabble_chars = $scrabble_chars -replace $char,""
		}
		if ($match){
			Write-Output([string]$word)
		}
	}
}
$answer | check


# 3
$answer = Import-Csv -Delimiter "`t" ./passwords.tsv | Group-Object category | Sort-Object @{Expression = "Count"; Descending = $True} | Select-Object Count,Name
$answer | check


# 4
$answer  = Import-Csv -Delimiter "`t" ./passwords.tsv | Sort-Object {$_.Password.Length}, {$_.Password} | Where-Object category -EQ "names" | Select-Object Password
$answer | check
