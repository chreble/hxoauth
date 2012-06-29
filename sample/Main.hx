package ;

import chx.hash.HMAC;
import chx.hash.Sha1;
import haxe.SHA1;
import neko.Lib;
import hxoauth.OAuth;
import utils.Base64;

/**
 * ...
 * @author Renaud Bardet
 */

class Main 
{
	
	static function main() 
	{
		
		var consumer_key = "key" ;
		var consumer_secret = "secret" ;
		
		var user_key = "accesskey" ;
		var user_secret = "accesssecret" ;
		
		var server_url = "http://term.ie/oauth/example/echo_api.php?plop=plop" ;
		
		var oaClient = OAuth.connect( consumer_key, consumer_secret ) ;
		oaClient.token = new Token(user_key, user_secret) ;
		trace( oaClient.request( server_url, GET ) ) ;
		
	}
	
}