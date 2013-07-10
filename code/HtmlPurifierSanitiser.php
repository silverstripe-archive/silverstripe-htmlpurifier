<?php

/**
 * Class HtmlPurifierSanitiser
 *
 * Replaces HtmlEditorSanitiser (which implements the TinyMCE valid_elements whitelist rules) with
 * a sanitiser based on HTMLPurifier
 *
 * TinyMCE's whitelist isn't capable of (for instance) allowing hrefs to contain
 * regular http: links but not javascript: links, and so doesn't completely eliminate XSS potential
 *
 * This class uses the TinyMCE whitelist, but only as a reference for instructions it gives to
 * HTMLPurifier, which is a library designed specifically for filtering HTML to remove XSS vectors
 *
 * Note that these features in TinyMCE whitelists are not supported:
 *
 * - Wildcards (on elements or attributes)
 * - Default and Forced attribute values
 */
class HtmlPurifierSanitiser extends HtmlEditorSanitiser {

	/**
	 * Should we add any extra elements or attributes that aren't in the default HTMLPurifier whitelist but are
	 * in the TinyMCE whitelist?
	 *
	 * If yes, you can use the whitelist to add HTML5 elements, but also attributes that break XSS protection
	 * If no, you can only use HTML4 elements, but it's almost certain you're protected from XSS
	 *
	 * @config
	 * @var bool
	 */
	private static $allow_extras = true;

	protected $purifierConfig;

	public function __construct(HtmlEditorConfig $config) {
		parent::__construct($config);
		$this->purifierConfig = $this->buildPurifierConfig();
	}

	protected function buildPurifierConfig() {
		$config = HTMLPurifier_Config::createDefault();

		// See http://htmlpurifier.org/docs/enduser-id.html
		$config->set('Attr.EnableID', true);

		// Make sure cached files get stored somewhere we know the webserver can write to
		$cacheDir = TEMP_FOLDER.'/htmlpurifier';
		if(!is_dir($cacheDir)) mkdir($cacheDir, 0700);

		$config->set('Cache.SerializerPath', $cacheDir);

		$allowedElements = array();
		$allowedAttributes = array();

		foreach($this->elements as $el => $eldef) {
			$allowedElements[$el] = true;
			foreach($eldef->attributes as $attr => $attrdef) {
				$allowedAttributes["$el.$attr"] = true;
			}
		}

		$config->set('HTML.AllowedElements', $allowedElements);
		$config->set('HTML.AllowedAttributes', $allowedAttributes);

		if (Config::inst()->get('HtmlPurifierSanitiser', 'allow_extras')) {
			$config->set('HTML.DefinitionID', 'autogen_'.sha1(serialize($this->elements)));
			$config->set('HTML.DefinitionRev', 1);
			if(!Director::isLive()) $config->set('Cache.DefinitionImpl', null);

			if($def = $config->maybeGetRawHTMLDefinition()) {
				$html4 = HTMLPurifier_Config::createDefault()->getHTMLDefinition(false, false);

				foreach($this->elements as $el => $eldef) {
					if(!isset($html4->info[$el])) {
						$def->addElement($el, 'Inline', 'Flow', '', array());
					}

					foreach($eldef->attributes as $attr => $attrdef) {
						$required = !empty($attrdef->required);

						if(!isset($html4->info[$el]->attr[$attr])) {
							if(!empty($attrdef->validValues)) {
								$type = 'Enum#'.implode(',', $attrdef->validValues);
							}
							else {
								$type = 'Text';
							}

							$def->addAttribute($el, $attr . ($required ? '*' : ''), $type);
						}
					}
				}
			}
		}

		return $config;
	}

	public function sanitise (SS_HTMLValue $html) {
		$dirty = $html->getContent();

		$purifier = new HTMLPurifier($this->purifierConfig);
		$clean = $purifier->purify($dirty);

		$html->setContent($clean);
	}
}
