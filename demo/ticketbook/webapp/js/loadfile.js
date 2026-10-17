// Wires the "Load from file" button to the input field: the chosen file's text replaces the field's value.
document.addEventListener( "DOMContentLoaded", function() {
	var button = document.getElementById( "loadbutton" );
	var chooser = document.getElementById( "loadfile" );
	var target = document.getElementById( "input" );
	if ( !button || !chooser || !target ) return;
	button.addEventListener( "click", function() { chooser.click(); } );
	chooser.addEventListener( "change", function() {
		var file = chooser.files[0];
		if ( !file ) return;
		var reader = new FileReader();
		reader.onload = function() { target.value = reader.result; };
		reader.readAsText( file );
		chooser.value = "";
	} );
} );
