//============================================================================//
// This file provides JavaScript support for the SQRL API test and demo page. //
//============================================================================//

var syncQuery1 = window.XMLHttpRequest ? new window.XMLHttpRequest() : new ActiveXObject('MSXML2.XMLHTTP.3.0');
var syncQuery2 = window.XMLHttpRequest ? new window.XMLHttpRequest() : new ActiveXObject('MSXML2.XMLHTTP.3.0');
var mixedProbe = new Image();
var gifProbe = new Image(); 					// create an instance of a memory-based probe image
var localhostRoot = 'http://localhost:25519/';	// the SQRL client listening URL root
var sqrlApiDomain = '{{.RootURL}}';	// the location of the SQRL server
var imageProbeUrl = 'http://www.rebindtest.com/open.gif';
Date.now = Date.now || function() { return (+new Date()) };	// add old browser Date.now() support
var sqrlNut, pagNut, sqrlUrl, sqrlPng;

//============================================================================//
// This function is invoked once when the page is loaded. It queries the SQRL //
// API to obtain a unique browser-session-cookie-based NUT, which it plugs in //
// to the HREF of the "Sign in with SQRL" link/button.                        //
//============================================================================//
function getSqrlNut() {
	syncQuery2.open( 'GET', sqrlApiDomain + '/nut.sqrl' );		// the page's DOM is loaded
	syncQuery2.onreadystatechange = function() {
		if ( syncQuery2.readyState === 4 ) {
			if ( syncQuery2.status === 200 ) {
				setNuts(syncQuery2.responseText);
				sqrlUrl = sqrlApiDomain.replace('https:','sqrl:') + '/cli.sqrl?' + sqrlNut;
				sqrlNut = sqrlNut.substr(sqrlNut.indexOf("nut="), 16);	// trim for just the 'nut={...}'
				sqrlPng = sqrlApiDomain + '/png.sqrl?' + sqrlNut;
				if (x = document.getElementById("sqrl")) x.href = sqrlUrl;
				if (x = document.getElementById("qrimg")) x.src = sqrlPng;
				pollForNextPage();	// start our next page checking
				} else {
				setTimeout(getSqrlNut, 100); // if our request for a /nut.sqrl fails, wait 10msec and retry
			}
		}	
	};
	syncQuery2.send(); // initiate the query to obtain the page's SQRL nut
};

function setNuts(responseText) {
	console.log("Resptext: "+ responseText)
	var pairs = responseText.split('&');
	for (var i = 0; i < pairs.length; i++) {
		if (pairs[i].indexOf("pag") == 0) {
			pagNut = pairs[i];
			break;
		}
	}
	if (i < pairs.length) {
		// remove the pag pair
		pairs.splice(i, 1)
	}
	sqrlNut = pairs.join("&")
}

//============================================================================//
//    This function is first called once the page has obtained a SQRL NUT.    //
//    It begins periodically querying for a next page to switch to.           //
//============================================================================//
function pollForNextPage() {
	if (document.hidden) {					// before probing for any page change, we check to 
		setTimeout(pollForNextPage, 500);	// see whether the page is visible. If the user is 
		return;								// not viewing the page, check again in 5 seconds.
	}
	syncQuery1.open( 'GET', sqrlApiDomain + '/pag.sqrl?' + sqrlNut + (pagNut ? "&" + pagNut : ""));	// the page is visible, so let's check for any update
	syncQuery1.onreadystatechange = function() {
		if ( syncQuery1.readyState === 4 ) {
			if ( syncQuery1.status === 200 ) {
				var cpsUrl = syncQuery1.responseText
				document.location.href = cpsUrl;
			} else {
				setTimeout(pollForNextPage, 500); // if we do not obtain a /pag.sqrl, wait 1/2 second and retry
			}
		}	
	};
	syncQuery1.send(); // initiate the query to the 'sync.txt' object.
};

getSqrlNut(); // get a fresh nut for the page, setup URLs and begin probing for any page change.


//============================================================================//
// The following block of code drives the experimental display of a notice to //
// alert and inform SQRL users when their web browser has been altered to not //
// retrieve and display passive mixed-content images... which is non-default. //
//============================================================================//
function showMessage() { document.getElementById("mixed").style.display = "block" };
probeImage = document.getElementById("probe");
setTimeout( function(){ if ( probeImage.height == 0 ) showMessage() }, 2000 );
probeImage.onerror = function() { showMessage() };
probeImage.src = imageProbeUrl;


//============================================================================//
// When we have a localhost CPS server present in the system, the test image  //
// probe will succeed. When it does we jump this browser to the localhost CPS //
// URL with the SQRL authentication URL base64url-encoded into the asset tag. //
//============================================================================//
gifProbe.onload = function() {  // define our load-success function
	// base64url-encode our CPS-jump URL. This replaces '/' with '_' and '+' with '-' and removes all trailing '='s
	var encodedSqrlUrl = window.btoa(sqrlUrl).replace(/\//,"_").replace(/\+/,"-").replace(/=+$/,"");
	document.location.href = localhostRoot + encodedSqrlUrl;
};


//============================================================================//
//  This is first called when we click the "Sign In" button to begin probing  //
//  for the presence of a localhost CPS server. It waits 250 ms then retries. //
//============================================================================//
gifProbe.onerror = function() { // define our load-failure function
	setTimeout( function(){ gifProbe.src = localhostRoot + Date.now() + '.gif';	}, 100 );
};
