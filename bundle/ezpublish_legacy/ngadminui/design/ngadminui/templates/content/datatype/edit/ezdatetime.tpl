{* The calendar of the icon below (showDatePicker()): Exponential UI's exp::datepicker where the legacy kernel has
   it instead of YUI, else YUI 2's calendar with ezdatepicker.js *}
{switch match=ngadminui_js_library()}
{case match='expui'}
{ezscript_require( array( 'ezjsc::jquery', 'exp::core::shared', 'exp::datepicker' ) )}
{ezcss_require( array( 'exp/core.css', 'exp/datepicker.css' ) )}
{/case}
{case match='yui'}
{* the group name in a variable: a constant ezini() is read when the template is compiled, which reports the
   setting missing on a legacy kernel without YUI although this branch never runs there *}
{def $ngadminui_ezjscore_group = 'eZJSCore'
     $base = ezini( $ngadminui_ezjscore_group, 'LocalScriptBasePath', 'ezjscore.ini' )}

{ezscript_require( 'ezjsc::yui2' )}
{ezcss_require( concat( '/', $base.yui2, 'calendar/assets/calendar.css' ) )}

<script type="text/javascript">
(function() {ldelim}
    var loader = new YAHOO.util.YUILoader(YUI2_config);

    loader.addModule({ldelim}
        name: 'datepicker',
        type: 'js',
        fullpath: '{"javascript/ezdatepicker.js"|ezdesign( 'no' )}',
        requires: ["calendar"],
        after: ["calendar"],
        skinnable: false
    {rdelim});

    loader.require(["datepicker"]);
    loader.insert();
{rdelim})();
</script>
{undef $base $ngadminui_ezjscore_group}
{/case}
{case}{/case}
{/switch}

{default attribute_base=ContentObjectAttribute}
{if ne( $attribute_base, 'ContentObjectAttribute' )}
    {def $id_base = concat( 'ezcoa-', $attribute_base, '-', $attribute.contentclassattribute_id, '_', $attribute.contentclass_attribute_identifier )}
{else}
    {def $id_base = concat( 'ezcoa-', $attribute.contentclassattribute_id, '_', $attribute.contentclass_attribute_identifier )}
{/if}

<div class="form-inline">
    <div class="date form-group">
        <div class="form-group">
            <label for="{$id_base}_year">{'Year'|i18n( 'design/admin/content/datatype' )}:</label>
            <input id="{$id_base}_year" class="form-control ezcc-{$attribute.object.content_class.identifier} ezcca-{$attribute.object.content_class.identifier}_{$attribute.contentclass_attribute_identifier}" type="text" name="{$attribute_base}_datetime_year_{$attribute.id}" size="5" value="{section show=$attribute.content.is_valid}{$attribute.content.year}{/section}" />
        </div>

        <div class="form-group">
            <label for="{$id_base}_month">{'Month'|i18n( 'design/admin/content/datatype' )}:</label>
            <input id="{$id_base}_month"  class="form-control ezcc-{$attribute.object.content_class.identifier} ezcca-{$attribute.object.content_class.identifier}_{$attribute.contentclass_attribute_identifier}" type="text" name="{$attribute_base}_datetime_month_{$attribute.id}" size="3" value="{section show=$attribute.content.is_valid}{$attribute.content.month}{/section}" />
        </div>

        <div class="form-group">
            <label for="{$id_base}_day">{'Day'|i18n( 'design/admin/content/datatype' )}:</label>
            <input id="{$id_base}_day" class="form-control ezcc-{$attribute.object.content_class.identifier} ezcca-{$attribute.object.content_class.identifier}_{$attribute.contentclass_attribute_identifier}" type="text" name="{$attribute_base}_datetime_day_{$attribute.id}" size="3" value="{section show=$attribute.content.is_valid}{$attribute.content.day}{/section}" />
        </div>
        <div class="form-group">
            <span class="datepicker-icon" id="{$attribute_base}_datetime_cal_{$attribute.id}" onclick="showDatePicker( '{$attribute_base}', '{$attribute.id}', 'datetime' );"><i class="fa fa-calendar"></i></span>
            <div id="{$attribute_base}_datetime_cal_container_{$attribute.id}" class="ngadminui-datepicker-container"></div>
            &nbsp;
            &nbsp;
            &nbsp;
            &nbsp;
        </div>
    </div>

    <div class="time form-group">
        <div class="form-group">
            <label for="{$id_base}_hour">{'Hour'|i18n( 'design/admin/content/datatype' )}:</label>
            <input id="{$id_base}_hour" class="form-control ezcc-{$attribute.object.content_class.identifier} ezcca-{$attribute.object.content_class.identifier}_{$attribute.contentclass_attribute_identifier}" type="text" name="{$attribute_base}_datetime_hour_{$attribute.id}" size="3" value="{section show=$attribute.content.is_valid}{$attribute.content.hour}{/section}" />
        </div>

        <div class="form-group">
            <label for="{$id_base}_minute">{'Minute'|i18n( 'design/admin/content/datatype' )}:</label>
            <input id="{$id_base}_minute" class="form-control ezcc-{$attribute.object.content_class.identifier} ezcca-{$attribute.object.content_class.identifier}_{$attribute.contentclass_attribute_identifier}" type="text" name="{$attribute_base}_datetime_minute_{$attribute.id}" size="3" value="{section show=$attribute.content.is_valid}{$attribute.content.minute}{/section}" />
        </div>

        {if $attribute.contentclass_attribute.data_int2|eq(1)}
            <div class="form-group">
                <label for="{$id_base}_second">{'Second'|i18n( 'design/standard/content/datatype' )}:</label>
                <input id="{$id_base}_second" class="form-control ezcc-{$attribute.object.content_class.identifier} ezcca-{$attribute.object.content_class.identifier}_{$attribute.contentclass_attribute_identifier}" type="text" name="{$attribute_base}_datetime_second_{$attribute.id}" size="3" value="{if $attribute.content.is_valid}{$attribute.content.second}{/if}" />
            </div>
        {/if}

    </div>
</div>

{/default}
