#define WIZARD_GLADE_CONTENTS "\
<\?xml version=\"1.0\" encoding=\"UTF-8\"\?>\
<interface>\
  <requires lib=\"gtk+\" version=\"2.16\"/>\
  <!-- interface-naming-policy toplevel-contextual -->\
  <object class=\"GtkWindow\" id=\"window0\">\
    <property name=\"can_focus\">False</property>\
    <child>\
      <object class=\"GtkVBox\" id=\"page_0\">\
        <property name=\"visible\">True</property>\
        <property name=\"can_focus\">False</property>\
        <property name=\"border_width\">3</property>\
        <property name=\"spacing\">3</property>\
        <child>\
          <object class=\"GtkLabel\" id=\"lbl_cd_reason\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
            <property name=\"xalign\">0</property>\
            <property name=\"yalign\">0</property>\
            <property name=\"wrap\">True</property>\
            <attributes>\
              <attribute name=\"style\" value=\"normal\"/>\
              <attribute name=\"weight\" value=\"bold\"/>\
              <attribute name=\"foreground\" value=\"#ffff00000000\"/>\
            </attributes>\
          </object>\
          <packing>\
            <property name=\"expand\">False</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">0</property>\
          </packing>\
        </child>\
        <child>\
          <object class=\"GtkLabel\" id=\"label7\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
            <property name=\"xalign\">0</property>\
            <property name=\"yalign\">0</property>\
            <property name=\"label\" translatable=\"yes\">On the following screens, you will be asked to describe how the problem occurred, to choose how to analyze the problem (if needed), to review collected data, and to choose where the problem should be reported. Click 'Forward' to proceed.</property>\
            <property name=\"wrap\">True</property>\
          </object>\
          <packing>\
            <property name=\"expand\">False</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">1</property>\
          </packing>\
        </child>\
        <child>\
          <object class=\"GtkExpander\" id=\"expander1\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">True</property>\
            <child>\
              <object class=\"GtkScrolledWindow\" id=\"container_details1\">\
                <property name=\"visible\">True</property>\
                <property name=\"can_focus\">True</property>\
                <property name=\"shadow_type\">out</property>\
                <child>\
                  <object class=\"GtkTreeView\" id=\"tv_details\">\
                    <property name=\"visible\">True</property>\
                    <property name=\"can_focus\">True</property>\
                  </object>\
                </child>\
              </object>\
            </child>\
            <child type=\"label\">\
              <object class=\"GtkLabel\" id=\"dump_elements\">\
                <property name=\"visible\">True</property>\
                <property name=\"can_focus\">False</property>\
                <property name=\"label\" translatable=\"yes\">Details</property>\
              </object>\
            </child>\
          </object>\
          <packing>\
            <property name=\"expand\">True</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">2</property>\
          </packing>\
        </child>\
      </object>\
    </child>\
  </object>\
  <object class=\"GtkWindow\" id=\"window1\">\
    <property name=\"can_focus\">False</property>\
    <child>\
      <object class=\"GtkVBox\" id=\"page_1\">\
        <property name=\"visible\">True</property>\
        <property name=\"can_focus\">False</property>\
        <property name=\"border_width\">10</property>\
        <property name=\"spacing\">3</property>\
        <child>\
          <object class=\"GtkLabel\" id=\"label1\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
            <property name=\"xalign\">0</property>\
            <property name=\"yalign\">0</property>\
            <property name=\"label\" translatable=\"yes\">How did this problem happen (step-by-step)\? How can it be reproduced\? Any additional comments useful for diagnosing the problem\? Please use English if possible.</property>\
            <property name=\"wrap\">True</property>\
          </object>\
          <packing>\
            <property name=\"expand\">False</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">0</property>\
          </packing>\
        </child>\
        <child>\
          <object class=\"GtkScrolledWindow\" id=\"scrolledwindow4\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">True</property>\
            <property name=\"shadow_type\">out</property>\
            <child>\
              <object class=\"GtkTextView\" id=\"tv_comment\">\
                <property name=\"visible\">True</property>\
                <property name=\"can_focus\">True</property>\
                <property name=\"wrap_mode\">word</property>\
              </object>\
            </child>\
          </object>\
          <packing>\
            <property name=\"expand\">True</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">1</property>\
          </packing>\
        </child>\
        <child>\
          <object class=\"GtkEventBox\" id=\"eb_comment\">\
            <property name=\"can_focus\">False</property>\
            <child>\
              <object class=\"GtkLabel\" id=\"label5\">\
                <property name=\"visible\">True</property>\
                <property name=\"can_focus\">False</property>\
                <property name=\"label\" translatable=\"yes\">You need to fill the how to before you can proceed...</property>\
                <property name=\"single_line_mode\">True</property>\
              </object>\
            </child>\
          </object>\
          <packing>\
            <property name=\"expand\">False</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">2</property>\
          </packing>\
        </child>\
        <child>\
          <object class=\"GtkLabel\" id=\"label3\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
            <property name=\"xalign\">0</property>\
            <property name=\"yalign\">0</property>\
            <property name=\"label\" translatable=\"yes\">&lt;b&gt;Your comments are not private.&lt;/b&gt; They may be included into publicly visible problem reports.</property>\
            <property name=\"use_markup\">True</property>\
            <property name=\"wrap\">True</property>\
          </object>\
          <packing>\
            <property name=\"expand\">False</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">3</property>\
          </packing>\
        </child>\
        <child>\
          <object class=\"GtkCheckButton\" id=\"cb_no_comment\">\
            <property name=\"label\" translatable=\"yes\">I don't know what caused this problem</property>\
            <property name=\"use_action_appearance\">False</property>\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">True</property>\
            <property name=\"receives_default\">False</property>\
            <property name=\"xalign\">0</property>\
            <property name=\"draw_indicator\">True</property>\
          </object>\
          <packing>\
            <property name=\"expand\">False</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">4</property>\
          </packing>\
        </child>\
      </object>\
    </child>\
  </object>\
  <object class=\"GtkWindow\" id=\"window10\">\
    <property name=\"can_focus\">False</property>\
    <child>\
      <object class=\"GtkVBox\" id=\"page_4\">\
        <property name=\"visible\">True</property>\
        <property name=\"can_focus\">False</property>\
        <property name=\"border_width\">10</property>\
        <property name=\"spacing\">3</property>\
        <child>\
          <object class=\"GtkLabel\" id=\"lbl_page7\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
            <property name=\"xalign\">0</property>\
            <property name=\"label\" translatable=\"yes\">Select additional files to attach to the report:</property>\
            <property name=\"use_markup\">True</property>\
            <property name=\"justify\">fill</property>\
            <property name=\"wrap\">True</property>\
          </object>\
          <packing>\
            <property name=\"expand\">True</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">0</property>\
          </packing>\
        </child>\
        <child>\
          <object class=\"GtkVBox\" id=\"vb_collectors\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
            <child>\
              <placeholder/>\
            </child>\
          </object>\
          <packing>\
            <property name=\"expand\">True</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">1</property>\
          </packing>\
        </child>\
        <child>\
          <object class=\"GtkHBox\" id=\"hbox4\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
            <child>\
              <object class=\"GtkButton\" id=\"button_cfg3\">\
                <property name=\"label\">gtk-preferences</property>\
                <property name=\"use_action_appearance\">False</property>\
                <property name=\"visible\">True</property>\
                <property name=\"can_focus\">True</property>\
                <property name=\"receives_default\">True</property>\
                <property name=\"use_underline\">True</property>\
                <property name=\"use_stock\">True</property>\
                <property name=\"image_position\">right</property>\
              </object>\
              <packing>\
                <property name=\"expand\">False</property>\
                <property name=\"fill\">False</property>\
                <property name=\"position\">0</property>\
              </packing>\
            </child>\
            <child>\
              <object class=\"GtkAlignment\" id=\"alignment5\">\
                <property name=\"visible\">True</property>\
                <property name=\"can_focus\">False</property>\
                <child>\
                  <placeholder/>\
                </child>\
              </object>\
              <packing>\
                <property name=\"expand\">True</property>\
                <property name=\"fill\">True</property>\
                <property name=\"position\">1</property>\
              </packing>\
            </child>\
          </object>\
          <packing>\
            <property name=\"expand\">False</property>\
            <property name=\"fill\">False</property>\
            <property name=\"position\">2</property>\
          </packing>\
        </child>\
      </object>\
    </child>\
  </object>\
  <object class=\"GtkWindow\" id=\"window11\">\
    <property name=\"can_focus\">False</property>\
    <child>\
      <object class=\"GtkVBox\" id=\"page_5\">\
        <property name=\"visible\">True</property>\
        <property name=\"can_focus\">False</property>\
        <property name=\"border_width\">10</property>\
        <property name=\"spacing\">3</property>\
        <child>\
          <object class=\"GtkLabel\" id=\"lbl_collect_log\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
            <property name=\"xalign\">0</property>\
            <property name=\"label\" translatable=\"yes\">Collecting did not start yet</property>\
            <property name=\"use_markup\">True</property>\
            <property name=\"wrap\">True</property>\
          </object>\
          <packing>\
            <property name=\"expand\">False</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">0</property>\
          </packing>\
        </child>\
        <child>\
          <object class=\"GtkScrolledWindow\" id=\"scrolledwindow7\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">True</property>\
            <property name=\"shadow_type\">out</property>\
            <child>\
              <object class=\"GtkTextView\" id=\"tv_collect_log\">\
                <property name=\"visible\">True</property>\
                <property name=\"can_focus\">True</property>\
                <property name=\"editable\">False</property>\
                <property name=\"accepts_tab\">False</property>\
              </object>\
            </child>\
          </object>\
          <packing>\
            <property name=\"expand\">True</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">1</property>\
          </packing>\
        </child>\
      </object>\
    </child>\
  </object>\
  <object class=\"GtkWindow\" id=\"window2\">\
    <property name=\"can_focus\">False</property>\
    <child>\
      <object class=\"GtkVBox\" id=\"page_2\">\
        <property name=\"visible\">True</property>\
        <property name=\"can_focus\">False</property>\
        <property name=\"border_width\">10</property>\
        <property name=\"spacing\">3</property>\
        <child>\
          <object class=\"GtkLabel\" id=\"lbl_page5\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
            <property name=\"xalign\">0</property>\
            <property name=\"label\" translatable=\"yes\">Select how you would like to analyze the problem:</property>\
            <property name=\"wrap\">True</property>\
          </object>\
          <packing>\
            <property name=\"expand\">True</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">0</property>\
          </packing>\
        </child>\
        <child>\
          <object class=\"GtkVBox\" id=\"vb_analyzers\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
            <child>\
              <placeholder/>\
            </child>\
          </object>\
          <packing>\
            <property name=\"expand\">True</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">1</property>\
          </packing>\
        </child>\
        <child>\
          <object class=\"GtkHBox\" id=\"hbox2\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
            <child>\
              <object class=\"GtkButton\" id=\"button_cfg1\">\
                <property name=\"label\">gtk-preferences</property>\
                <property name=\"use_action_appearance\">False</property>\
                <property name=\"visible\">True</property>\
                <property name=\"can_focus\">True</property>\
                <property name=\"receives_default\">True</property>\
                <property name=\"use_underline\">True</property>\
                <property name=\"use_stock\">True</property>\
                <property name=\"image_position\">right</property>\
              </object>\
              <packing>\
                <property name=\"expand\">False</property>\
                <property name=\"fill\">False</property>\
                <property name=\"position\">0</property>\
              </packing>\
            </child>\
            <child>\
              <object class=\"GtkAlignment\" id=\"alignment3\">\
                <property name=\"visible\">True</property>\
                <property name=\"can_focus\">False</property>\
                <child>\
                  <placeholder/>\
                </child>\
              </object>\
              <packing>\
                <property name=\"expand\">True</property>\
                <property name=\"fill\">True</property>\
                <property name=\"position\">1</property>\
              </packing>\
            </child>\
          </object>\
          <packing>\
            <property name=\"expand\">False</property>\
            <property name=\"fill\">False</property>\
            <property name=\"position\">2</property>\
          </packing>\
        </child>\
      </object>\
    </child>\
  </object>\
  <object class=\"GtkWindow\" id=\"window3\">\
    <property name=\"can_focus\">False</property>\
    <child>\
      <object class=\"GtkVBox\" id=\"page_3\">\
        <property name=\"visible\">True</property>\
        <property name=\"can_focus\">False</property>\
        <property name=\"border_width\">10</property>\
        <property name=\"spacing\">3</property>\
        <child>\
          <object class=\"GtkLabel\" id=\"lbl_analyze_log\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
            <property name=\"xalign\">0</property>\
            <property name=\"label\" translatable=\"yes\">Analyzing did not start yet</property>\
            <property name=\"use_markup\">True</property>\
            <property name=\"justify\">fill</property>\
            <property name=\"single_line_mode\">True</property>\
            <property name=\"max_width_chars\">64</property>\
          </object>\
          <packing>\
            <property name=\"expand\">False</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">0</property>\
          </packing>\
        </child>\
        <child>\
          <object class=\"GtkProgressBar\" id=\"pb_analyze\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
          </object>\
          <packing>\
            <property name=\"expand\">False</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">1</property>\
          </packing>\
        </child>\
        <child>\
          <object class=\"GtkExpander\" id=\"expand_analyze\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">True</property>\
            <child>\
              <object class=\"GtkScrolledWindow\" id=\"scrolledwindow1\">\
                <property name=\"visible\">True</property>\
                <property name=\"can_focus\">True</property>\
                <property name=\"shadow_type\">out</property>\
                <child>\
                  <object class=\"GtkTextView\" id=\"tv_analyze_log\">\
                    <property name=\"visible\">True</property>\
                    <property name=\"can_focus\">True</property>\
                    <property name=\"editable\">False</property>\
                    <property name=\"accepts_tab\">False</property>\
                  </object>\
                </child>\
              </object>\
            </child>\
            <child type=\"label\">\
              <object class=\"GtkLabel\" id=\"lbl_analyze_show_log\">\
                <property name=\"visible\">True</property>\
                <property name=\"can_focus\">False</property>\
                <property name=\"label\" translatable=\"yes\">Show log</property>\
              </object>\
            </child>\
          </object>\
          <packing>\
            <property name=\"expand\">True</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">2</property>\
          </packing>\
        </child>\
        <child>\
          <object class=\"GtkHBox\" id=\"box2\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
            <child>\
              <object class=\"GtkButton\" id=\"btn_cancel_analyze\">\
                <property name=\"label\">gtk-stop</property>\
                <property name=\"use_action_appearance\">False</property>\
                <property name=\"visible\">True</property>\
                <property name=\"can_focus\">True</property>\
                <property name=\"receives_default\">True</property>\
                <property name=\"use_stock\">True</property>\
              </object>\
              <packing>\
                <property name=\"expand\">False</property>\
                <property name=\"fill\">True</property>\
                <property name=\"position\">0</property>\
              </packing>\
            </child>\
          </object>\
          <packing>\
            <property name=\"expand\">False</property>\
            <property name=\"fill\">False</property>\
            <property name=\"position\">3</property>\
          </packing>\
        </child>\
      </object>\
    </child>\
  </object>\
  <object class=\"GtkWindow\" id=\"window4\">\
    <property name=\"can_focus\">False</property>\
    <child>\
      <object class=\"GtkVBox\" id=\"page_6_report\">\
        <property name=\"visible\">True</property>\
        <property name=\"can_focus\">False</property>\
        <property name=\"border_width\">10</property>\
        <property name=\"spacing\">3</property>\
        <child>\
          <object class=\"GtkLabel\" id=\"lbl_page3\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
            <property name=\"xalign\">0</property>\
            <property name=\"label\" translatable=\"yes\">Select how you would like to report the problem:</property>\
            <property name=\"use_markup\">True</property>\
            <property name=\"justify\">fill</property>\
            <property name=\"wrap\">True</property>\
          </object>\
          <packing>\
            <property name=\"expand\">True</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">0</property>\
          </packing>\
        </child>\
        <child>\
          <object class=\"GtkVBox\" id=\"vb_reporters\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
            <child>\
              <placeholder/>\
            </child>\
          </object>\
          <packing>\
            <property name=\"expand\">True</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">1</property>\
          </packing>\
        </child>\
        <child>\
          <object class=\"GtkHBox\" id=\"hbox3\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
            <child>\
              <object class=\"GtkButton\" id=\"button_cfg2\">\
                <property name=\"label\">gtk-preferences</property>\
                <property name=\"use_action_appearance\">False</property>\
                <property name=\"visible\">True</property>\
                <property name=\"can_focus\">True</property>\
                <property name=\"receives_default\">True</property>\
                <property name=\"use_underline\">True</property>\
                <property name=\"use_stock\">True</property>\
                <property name=\"image_position\">right</property>\
              </object>\
              <packing>\
                <property name=\"expand\">False</property>\
                <property name=\"fill\">False</property>\
                <property name=\"position\">0</property>\
              </packing>\
            </child>\
            <child>\
              <object class=\"GtkAlignment\" id=\"alignment4\">\
                <property name=\"visible\">True</property>\
                <property name=\"can_focus\">False</property>\
                <child>\
                  <placeholder/>\
                </child>\
              </object>\
              <packing>\
                <property name=\"expand\">True</property>\
                <property name=\"fill\">True</property>\
                <property name=\"position\">1</property>\
              </packing>\
            </child>\
          </object>\
          <packing>\
            <property name=\"expand\">False</property>\
            <property name=\"fill\">False</property>\
            <property name=\"position\">2</property>\
          </packing>\
        </child>\
      </object>\
    </child>\
  </object>\
  <object class=\"GtkWindow\" id=\"window5\">\
    <property name=\"can_focus\">False</property>\
    <property name=\"tooltip_text\" translatable=\"yes\">Use this button to generate more informative backtrace after you installed additional debug packages</property>\
    <child>\
      <object class=\"GtkVBox\" id=\"page_7_report\">\
        <property name=\"visible\">True</property>\
        <property name=\"can_focus\">False</property>\
        <property name=\"border_width\">10</property>\
        <property name=\"spacing\">3</property>\
        <child>\
          <object class=\"GtkNotebook\" id=\"notebook_edit\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">True</property>\
            <property name=\"scrollable\">True</property>\
            <child>\
              <placeholder/>\
            </child>\
            <child type=\"tab\">\
              <placeholder/>\
            </child>\
            <child>\
              <placeholder/>\
            </child>\
            <child type=\"tab\">\
              <placeholder/>\
            </child>\
            <child>\
              <placeholder/>\
            </child>\
            <child type=\"tab\">\
              <placeholder/>\
            </child>\
          </object>\
          <packing>\
            <property name=\"expand\">True</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">0</property>\
          </packing>\
        </child>\
        <child>\
          <object class=\"GtkHBox\" id=\"hbox1\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
            <property name=\"border_width\">5</property>\
            <child>\
              <object class=\"GtkHBox\" id=\"box_warning_area\">\
                <property name=\"visible\">True</property>\
                <property name=\"can_focus\">False</property>\
                <property name=\"no_show_all\">True</property>\
                <child>\
                  <object class=\"GtkImage\" id=\"image1\">\
                    <property name=\"visible\">True</property>\
                    <property name=\"can_focus\">False</property>\
                    <property name=\"stock\">gtk-dialog-warning</property>\
                    <property name=\"icon-size\">6</property>\
                  </object>\
                  <packing>\
                    <property name=\"expand\">False</property>\
                    <property name=\"fill\">False</property>\
                    <property name=\"position\">0</property>\
                  </packing>\
                </child>\
                <child>\
                  <object class=\"GtkVBox\" id=\"vbox6\">\
                    <property name=\"visible\">True</property>\
                    <property name=\"can_focus\">False</property>\
                    <child>\
                      <object class=\"GtkAlignment\" id=\"alignment1\">\
                        <property name=\"visible\">True</property>\
                        <property name=\"can_focus\">False</property>\
                        <child>\
                          <placeholder/>\
                        </child>\
                      </object>\
                      <packing>\
                        <property name=\"expand\">True</property>\
                        <property name=\"fill\">False</property>\
                        <property name=\"position\">0</property>\
                      </packing>\
                    </child>\
                    <child>\
                      <object class=\"GtkVBox\" id=\"box_warning_labels\">\
                        <property name=\"visible\">True</property>\
                        <property name=\"can_focus\">False</property>\
                        <child>\
                          <placeholder/>\
                        </child>\
                        <child>\
                          <placeholder/>\
                        </child>\
                        <child>\
                          <placeholder/>\
                        </child>\
                      </object>\
                      <packing>\
                        <property name=\"expand\">False</property>\
                        <property name=\"fill\">False</property>\
                        <property name=\"position\">1</property>\
                      </packing>\
                    </child>\
                    <child>\
                      <object class=\"GtkAlignment\" id=\"alignment2\">\
                        <property name=\"visible\">True</property>\
                        <property name=\"can_focus\">False</property>\
                        <child>\
                          <placeholder/>\
                        </child>\
                      </object>\
                      <packing>\
                        <property name=\"expand\">True</property>\
                        <property name=\"fill\">False</property>\
                        <property name=\"padding\">1</property>\
                        <property name=\"position\">2</property>\
                      </packing>\
                    </child>\
                  </object>\
                  <packing>\
                    <property name=\"expand\">True</property>\
                    <property name=\"fill\">True</property>\
                    <property name=\"position\">1</property>\
                  </packing>\
                </child>\
              </object>\
              <packing>\
                <property name=\"expand\">True</property>\
                <property name=\"fill\">True</property>\
                <property name=\"padding\">1</property>\
                <property name=\"position\">0</property>\
              </packing>\
            </child>\
            <child>\
              <object class=\"GtkVBox\" id=\"vbox5\">\
                <property name=\"visible\">True</property>\
                <property name=\"can_focus\">False</property>\
                <child>\
                  <object class=\"GtkHBox\" id=\"search_hbox\">\
                    <property name=\"visible\">True</property>\
                    <property name=\"can_focus\">False</property>\
                    <child>\
                      <object class=\"GtkEntry\" id=\"entry_search_bt\">\
                        <property name=\"visible\">True</property>\
                        <property name=\"can_focus\">True</property>\
                        <property name=\"invisible_char\">●</property>\
                        <property name=\"invisible_char_set\">True</property>\
                        <property name=\"secondary_icon_stock\">gtk-find</property>\
                        <property name=\"primary_icon_activatable\">False</property>\
                        <property name=\"secondary_icon_activatable\">True</property>\
                        <property name=\"primary_icon_sensitive\">True</property>\
                        <property name=\"secondary_icon_sensitive\">True</property>\
                      </object>\
                      <packing>\
                        <property name=\"expand\">False</property>\
                        <property name=\"fill\">False</property>\
                        <property name=\"position\">0</property>\
                      </packing>\
                    </child>\
                    <child>\
                      <object class=\"GtkVBox\" id=\"vbox1\">\
                        <property name=\"visible\">True</property>\
                        <property name=\"can_focus\">False</property>\
                        <child>\
                          <object class=\"GtkEventBox\" id=\"ev_search_up\">\
                            <property name=\"visible\">True</property>\
                            <property name=\"can_focus\">False</property>\
                            <child>\
                              <object class=\"GtkArrow\" id=\"arr_search_up\">\
                                <property name=\"visible\">True</property>\
                                <property name=\"can_focus\">False</property>\
                                <property name=\"arrow_type\">up</property>\
                              </object>\
                            </child>\
                          </object>\
                          <packing>\
                            <property name=\"expand\">True</property>\
                            <property name=\"fill\">True</property>\
                            <property name=\"position\">0</property>\
                          </packing>\
                        </child>\
                        <child>\
                          <object class=\"GtkEventBox\" id=\"ev_search_down\">\
                            <property name=\"visible\">True</property>\
                            <property name=\"can_focus\">False</property>\
                            <child>\
                              <object class=\"GtkArrow\" id=\"arr_search_down\">\
                                <property name=\"visible\">True</property>\
                                <property name=\"can_focus\">False</property>\
                                <property name=\"arrow_type\">down</property>\
                              </object>\
                            </child>\
                          </object>\
                          <packing>\
                            <property name=\"expand\">True</property>\
                            <property name=\"fill\">True</property>\
                            <property name=\"position\">1</property>\
                          </packing>\
                        </child>\
                      </object>\
                      <packing>\
                        <property name=\"expand\">False</property>\
                        <property name=\"fill\">False</property>\
                        <property name=\"position\">1</property>\
                      </packing>\
                    </child>\
                  </object>\
                  <packing>\
                    <property name=\"expand\">False</property>\
                    <property name=\"fill\">False</property>\
                    <property name=\"position\">0</property>\
                  </packing>\
                </child>\
                <child>\
                  <object class=\"GtkButton\" id=\"btn_refresh\">\
                    <property name=\"label\" translatable=\"yes\">Regenerate backtrace</property>\
                    <property name=\"use_action_appearance\">False</property>\
                    <property name=\"visible\">True</property>\
                    <property name=\"can_focus\">True</property>\
                    <property name=\"receives_default\">True</property>\
                    <signal name=\"clicked\" handler=\"on_b_refresh_clicked\" swapped=\"no\"/>\
                  </object>\
                  <packing>\
                    <property name=\"expand\">False</property>\
                    <property name=\"fill\">False</property>\
                    <property name=\"position\">1</property>\
                  </packing>\
                </child>\
              </object>\
              <packing>\
                <property name=\"expand\">False</property>\
                <property name=\"fill\">False</property>\
                <property name=\"pack_type\">end</property>\
                <property name=\"position\">1</property>\
              </packing>\
            </child>\
          </object>\
          <packing>\
            <property name=\"expand\">False</property>\
            <property name=\"fill\">False</property>\
            <property name=\"position\">1</property>\
          </packing>\
        </child>\
      </object>\
    </child>\
  </object>\
  <object class=\"GtkWindow\" id=\"window6\">\
    <property name=\"can_focus\">False</property>\
    <child>\
      <object class=\"GtkVBox\" id=\"page_8_report\">\
        <property name=\"visible\">True</property>\
        <property name=\"can_focus\">False</property>\
        <property name=\"border_width\">10</property>\
        <property name=\"spacing\">3</property>\
        <child>\
          <object class=\"GtkLabel\" id=\"lbl_page6\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
            <property name=\"xalign\">0</property>\
            <property name=\"label\" translatable=\"yes\">Click 'Apply' to start reporting</property>\
            <property name=\"justify\">fill</property>\
            <property name=\"wrap\">True</property>\
          </object>\
          <packing>\
            <property name=\"expand\">False</property>\
            <property name=\"fill\">False</property>\
            <property name=\"position\">0</property>\
          </packing>\
        </child>\
        <child>\
          <object class=\"GtkTable\" id=\"table1\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
            <property name=\"n_rows\">2</property>\
            <property name=\"n_columns\">2</property>\
            <property name=\"column_spacing\">10</property>\
            <child>\
              <object class=\"GtkLabel\" id=\"label4\">\
                <property name=\"visible\">True</property>\
                <property name=\"can_focus\">False</property>\
                <property name=\"xalign\">0</property>\
                <property name=\"label\" translatable=\"yes\">Size:</property>\
                <property name=\"justify\">right</property>\
                <attributes>\
                  <attribute name=\"weight\" value=\"bold\"/>\
                </attributes>\
              </object>\
              <packing>\
                <property name=\"top_attach\">1</property>\
                <property name=\"bottom_attach\">2</property>\
                <property name=\"x_options\">GTK_FILL</property>\
                <property name=\"y_options\"></property>\
              </packing>\
            </child>\
            <child>\
              <object class=\"GtkLabel\" id=\"label8\">\
                <property name=\"visible\">True</property>\
                <property name=\"can_focus\">False</property>\
                <property name=\"xalign\">0</property>\
                <property name=\"label\" translatable=\"yes\">Reporter(s):</property>\
                <property name=\"justify\">right</property>\
                <attributes>\
                  <attribute name=\"weight\" value=\"bold\"/>\
                </attributes>\
              </object>\
              <packing>\
                <property name=\"x_options\">GTK_FILL</property>\
                <property name=\"y_options\"></property>\
              </packing>\
            </child>\
            <child>\
              <object class=\"GtkLabel\" id=\"lbl_reporters\">\
                <property name=\"visible\">True</property>\
                <property name=\"can_focus\">False</property>\
                <property name=\"xalign\">0</property>\
              </object>\
              <packing>\
                <property name=\"left_attach\">1</property>\
                <property name=\"right_attach\">2</property>\
              </packing>\
            </child>\
            <child>\
              <object class=\"GtkLabel\" id=\"lbl_size\">\
                <property name=\"visible\">True</property>\
                <property name=\"can_focus\">False</property>\
                <property name=\"xalign\">0</property>\
              </object>\
              <packing>\
                <property name=\"left_attach\">1</property>\
                <property name=\"right_attach\">2</property>\
                <property name=\"top_attach\">1</property>\
                <property name=\"bottom_attach\">2</property>\
              </packing>\
            </child>\
          </object>\
          <packing>\
            <property name=\"expand\">False</property>\
            <property name=\"fill\">False</property>\
            <property name=\"position\">1</property>\
          </packing>\
        </child>\
        <child>\
          <object class=\"GtkScrolledWindow\" id=\"container_details2\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">True</property>\
            <property name=\"shadow_type\">out</property>\
            <child>\
              <placeholder/>\
            </child>\
          </object>\
          <packing>\
            <property name=\"expand\">True</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">2</property>\
          </packing>\
        </child>\
        <child>\
          <object class=\"GtkHBox\" id=\"box1\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
            <child>\
              <object class=\"GtkButton\" id=\"btn_add_file\">\
                <property name=\"label\" translatable=\"yes\">Attach a file</property>\
                <property name=\"use_action_appearance\">False</property>\
                <property name=\"visible\">True</property>\
                <property name=\"can_focus\">True</property>\
                <property name=\"receives_default\">True</property>\
              </object>\
              <packing>\
                <property name=\"expand\">False</property>\
                <property name=\"fill\">False</property>\
                <property name=\"position\">0</property>\
              </packing>\
            </child>\
            <child>\
              <placeholder/>\
            </child>\
          </object>\
          <packing>\
            <property name=\"expand\">False</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">3</property>\
          </packing>\
        </child>\
        <child>\
          <object class=\"GtkCheckButton\" id=\"cb_approve_bt\">\
            <property name=\"label\" translatable=\"yes\">I reviewed the data and _agree with submitting it</property>\
            <property name=\"use_action_appearance\">False</property>\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">True</property>\
            <property name=\"receives_default\">False</property>\
            <property name=\"tooltip_text\" translatable=\"yes\">If you are reporting to a remote server, make sure you removed all private data (such as usernames and passwords). Backtrace, command line, environment variables are the typical items in need of examining.</property>\
            <property name=\"use_underline\">True</property>\
            <property name=\"xalign\">0</property>\
            <property name=\"draw_indicator\">True</property>\
          </object>\
          <packing>\
            <property name=\"expand\">False</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">4</property>\
          </packing>\
        </child>\
      </object>\
    </child>\
  </object>\
  <object class=\"GtkWindow\" id=\"window7\">\
    <property name=\"can_focus\">False</property>\
    <child>\
      <object class=\"GtkVBox\" id=\"page_9_report\">\
        <property name=\"visible\">True</property>\
        <property name=\"can_focus\">False</property>\
        <property name=\"border_width\">10</property>\
        <property name=\"spacing\">3</property>\
        <child>\
          <object class=\"GtkLabel\" id=\"lbl_report_log\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
            <property name=\"xalign\">0</property>\
            <property name=\"label\" translatable=\"yes\">Reporting did not start yet</property>\
            <property name=\"use_markup\">True</property>\
            <property name=\"justify\">fill</property>\
            <property name=\"single_line_mode\">True</property>\
            <property name=\"max_width_chars\">64</property>\
          </object>\
          <packing>\
            <property name=\"expand\">False</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">0</property>\
          </packing>\
        </child>\
        <child>\
          <object class=\"GtkProgressBar\" id=\"pb_report\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
          </object>\
          <packing>\
            <property name=\"expand\">False</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">1</property>\
          </packing>\
        </child>\
        <child>\
          <object class=\"GtkExpander\" id=\"expand_report\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">True</property>\
            <child>\
              <object class=\"GtkScrolledWindow\" id=\"scrolledwindow6\">\
                <property name=\"visible\">True</property>\
                <property name=\"can_focus\">True</property>\
                <property name=\"shadow_type\">out</property>\
                <child>\
                  <object class=\"GtkTextView\" id=\"tv_report_log\">\
                    <property name=\"visible\">True</property>\
                    <property name=\"can_focus\">True</property>\
                    <property name=\"editable\">False</property>\
                    <property name=\"accepts_tab\">False</property>\
                  </object>\
                </child>\
              </object>\
            </child>\
            <child type=\"label\">\
              <object class=\"GtkLabel\" id=\"lbl_report_show_log\">\
                <property name=\"visible\">True</property>\
                <property name=\"can_focus\">False</property>\
                <property name=\"label\" translatable=\"yes\">Show log</property>\
              </object>\
            </child>\
          </object>\
          <packing>\
            <property name=\"expand\">True</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">2</property>\
          </packing>\
        </child>\
        <child>\
          <object class=\"GtkHBox\" id=\"box3\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
            <child>\
              <object class=\"GtkButton\" id=\"btn_cancel_report\">\
                <property name=\"label\">gtk-stop</property>\
                <property name=\"use_action_appearance\">False</property>\
                <property name=\"visible\">True</property>\
                <property name=\"can_focus\">True</property>\
                <property name=\"receives_default\">True</property>\
                <property name=\"use_stock\">True</property>\
              </object>\
              <packing>\
                <property name=\"expand\">False</property>\
                <property name=\"fill\">True</property>\
                <property name=\"position\">0</property>\
              </packing>\
            </child>\
            <child>\
              <placeholder/>\
            </child>\
          </object>\
          <packing>\
            <property name=\"expand\">False</property>\
            <property name=\"fill\">False</property>\
            <property name=\"position\">3</property>\
          </packing>\
        </child>\
      </object>\
    </child>\
  </object>\
  <object class=\"GtkWindow\" id=\"window8\">\
    <property name=\"can_focus\">False</property>\
    <child>\
      <object class=\"GtkVBox\" id=\"page_10_report\">\
        <property name=\"visible\">True</property>\
        <property name=\"can_focus\">False</property>\
        <property name=\"border_width\">10</property>\
        <property name=\"spacing\">3</property>\
        <child>\
          <object class=\"GtkLabel\" id=\"label2\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
            <property name=\"xalign\">0</property>\
            <property name=\"yalign\">0</property>\
            <property name=\"label\" translatable=\"yes\">Reporting has finished. You can close this window now.</property>\
            <property name=\"wrap\">True</property>\
          </object>\
          <packing>\
            <property name=\"expand\">False</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">0</property>\
          </packing>\
        </child>\
        <child>\
          <object class=\"GtkLabel\" id=\"label6\">\
            <property name=\"visible\">True</property>\
            <property name=\"can_focus\">False</property>\
            <property name=\"xalign\">0</property>\
            <property name=\"yalign\">0</property>\
            <property name=\"label\" translatable=\"yes\">If you want to report the problem to a different destination, collect additional information, or provide a better problem description and repeat reporting process, press 'Forward'.</property>\
            <property name=\"wrap\">True</property>\
          </object>\
          <packing>\
            <property name=\"expand\">False</property>\
            <property name=\"fill\">True</property>\
            <property name=\"position\">1</property>\
          </packing>\
        </child>\
        <child>\
          <placeholder/>\
        </child>\
      </object>\
    </child>\
  </object>\
  <object class=\"GtkWindow\" id=\"window9\">\
    <property name=\"can_focus\">False</property>\
    <child>\
      <object class=\"GtkVBox\" id=\"page_11_report\">\
        <property name=\"visible\">True</property>\
        <property name=\"can_focus\">False</property>\
        <property name=\"border_width\">10</property>\
        <property name=\"spacing\">3</property>\
        <child>\
          <placeholder/>\
        </child>\
        <child>\
          <placeholder/>\
        </child>\
        <child>\
          <placeholder/>\
        </child>\
      </object>\
    </child>\
  </object>\
</interface>\
"
