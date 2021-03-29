<?php
show_source(__FILE__);
include("flag.php");

$ANSWER = bin2hex(random_bytes(10));
echo "<p>Real Answer: ", $ANSWER, "</p>";

extract($_GET);
if (!empty($guess) && $guess == $ANSWER) {
    echo "<p>Correct!</p>";
    if (md5($token1) == sha1($token2)) echo FLAG;
} else {
    echo "Loser :/";
}
