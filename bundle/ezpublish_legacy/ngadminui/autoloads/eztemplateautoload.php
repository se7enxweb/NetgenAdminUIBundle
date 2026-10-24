<?php

$eZTemplateOperatorArray = array();

$eZTemplateOperatorArray[] = array(
    'class' => 'NgAdminUiTagsBundleOperator',
    'operator_names' => array( 'has_tags_bundle' )
);

// Which JavaScript library the legacy kernel provides for the admin widgets (Exponential UI or YUI). 'script' loads
// the class when the legacy autoload array has not been regenerated since the bundle was updated.
$eZTemplateOperatorArray[] = array(
    'script' => eZExtension::baseDirectory() . '/ngadminui/classes/ngadminuijavascriptoperator.php',
    'class' => 'NgAdminUiJavaScriptOperator',
    'operator_names' => array( 'ngadminui_js_library', 'ngadminui_has_template' )
);
