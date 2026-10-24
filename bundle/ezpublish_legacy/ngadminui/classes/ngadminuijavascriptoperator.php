<?php

/**
 * Tells the ngadminui templates which JavaScript library the legacy kernel provides for the admin widgets
 * (the sub-items table, the date pickers, the relation upload, the collapsible edit menus).
 *
 *   ngadminui_js_library()                  'expui' when Exponential UI (extension expui) is active and ezjscore
 *                                           no longer provides YUI; 'yui' when ezjscore still provides YUI
 *                                           (ezjsc::yui2 and ezjsc::yui3); 'none' when neither is there.
 *   ngadminui_has_template( 'a/b.tpl' )     true when the current design list has the template.
 *
 * A kernel that still ships YUI keeps the YUI code exactly as before, so its admin pages do not change.
 */
class NgAdminUiJavaScriptOperator
{
    /**
     * @var string|null
     */
    protected static $library = null;

    function operatorList()
    {
        return array( 'ngadminui_js_library', 'ngadminui_has_template' );
    }

    function namedParameterPerOperator()
    {
        return true;
    }

    function namedParameterList()
    {
        return array(
            'ngadminui_js_library' => array(),
            'ngadminui_has_template' => array(
                'path' => array( 'type' => 'string', 'required' => true, 'default' => '' )
            )
        );
    }

    function modify( $tpl, $operatorName, $operatorParameters, $rootNamespace, $currentNamespace, &$operatorValue, $namedParameters, $placement )
    {
        if ( $operatorName === 'ngadminui_js_library' )
        {
            $operatorValue = self::library();
        }
        else if ( $operatorName === 'ngadminui_has_template' )
        {
            $operatorValue = self::hasTemplate( $namedParameters['path'] );
        }
    }

    /**
     * @return string 'expui', 'yui' or 'none'
     */
    public static function library()
    {
        if ( self::$library === null )
        {
            if ( self::hasYui() )
            {
                self::$library = 'yui';
            }
            else if ( in_array( 'expui', eZExtension::activeExtensions(), true ) )
            {
                self::$library = 'expui';
            }
            else
            {
                self::$library = 'none';
            }
        }

        return self::$library;
    }

    /**
     * ezjscore provides YUI as long as it has the ezjsc::yui2 packer function; ezjscore 1.5.0 (Exponential 6.0.15)
     * removed it together with the YUI files.
     *
     * @return bool
     */
    public static function hasYui()
    {
        return class_exists( 'ezjscServerFunctionsJs' ) && method_exists( 'ezjscServerFunctionsJs', 'yui2' );
    }

    /**
     * @param string $path
     *
     * @return bool
     */
    public static function hasTemplate( $path )
    {
        $path = ltrim( (string) $path, '/' );
        if ( $path === '' )
        {
            return false;
        }

        $triedFiles = array();
        $match = eZTemplateDesignResource::fileMatch( eZTemplateDesignResource::allDesignBases(), 'templates', $path, $triedFiles );

        return is_array( $match );
    }
}
