import idaapi
import ida_kernwin
import ida_hexrays
import ida_typeinf
import os
from go_util.itab_typedef_maker import find_interface_implementations, replace_type
from go_util.itab_parser import parse_itab


def get_selected_member(form):
    out = ida_kernwin.listing_location_t()
    idaapi.get_custom_viewer_location(out, form)
    place = out.loc.place()
    place: ida_kernwin.tiplace_t = place.as_tiplace_t(place)
    ordinal = place.ordinal
    globals()["place"] = place
    globals()["out"] = out

    if "\x01%" not in out.text or "\x02%" not in out.text:
        if out.text:
            print("Could not find member name in selected line:", out.text)
        return None
    
    member_name = out.text.split("\x01%")[1].split("\x02%")[0]

    struct = ida_typeinf.tinfo_t()
    struct.get_numbered_type(ordinal)
    if not struct.is_struct():
        return None
    udt = ida_typeinf.udt_type_data_t()
    if not struct.get_udt_details(udt):
        return None
    for field in udt:
        if field.name == member_name:
            type_name = field.type.get_final_type_name()
            if not type_name or ("iface" not in type_name and "interface" not in type_name):
                return None
            return struct, str(field.type), field.offset
    return None

class Hooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        type = idaapi.get_widget_type(form)
        if type == idaapi.BWN_TILIST:
            if not get_selected_member(form):
                return
            idaapi.attach_action_to_popup(form, popup, ACTION_NAME, '')


class InterfaceTypeChooser(ida_kernwin.Choose):
    def __init__(self, interfaces: list):
        ida_kernwin.Choose.__init__(
            self,
            "Choose an interface implementation",
            [["Interface Implementation"]],
            flags=ida_kernwin.Choose.CH_MODAL,
        )
        self.items = interfaces

    def OnGetLine(self, n):
        name, _ = self.items[n]
        return [name.get_type_name()[len("iface_"):]]
    
    def OnGetEA(self, n):
        return self.items[n][1]

    def OnGetSize(self):
        return len(self.items)


interface_implementations = None

class InterfaceSpecializer(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        global interface_implementations
        form = ctx.widget
        member = get_selected_member(form)
        if not member:
            return
        struct, type, offset = member
        if interface_implementations is None:
            interface_implementations = find_interface_implementations()
        if type not in interface_implementations:
            type = type.rstrip("_1234567890")
            if type not in interface_implementations:
                ida_kernwin.warning(f"No concrete types found for interface {type}")
                return 1
        candidates = interface_implementations[type]
        chooser = InterfaceTypeChooser(candidates)
        idx = chooser.Show(modal=True)
        if idx < 0:
            ida_kernwin.warning("No interface implementation selected.")
            return 1
        selected_iface = chooser.items[idx]
        _, iface_ea = selected_iface
        _, iface_type = parse_itab(iface_ea)
        iface_type, _ = iface_type
        replace_type(struct, offset, iface_type)

        return 1

    def update(self, ctx):
        # Only enable if a struct is highlighted in Local Types
        widget = ida_kernwin.get_current_widget()
        if widget and ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_TILIST:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET

ACTION_NAME = "golang:interface_specializer"
ACTION_LABEL = "Specialize Interface"

class InterfaceSpecializerPlugin(idaapi.plugin_t):
    flags = 0
    comment = 'Sets concrete types for interfaces.'
    help = 'Sets concrete types for interfaces.'
    wanted_name = "Go Interface Specializer"
    wanted_hotkey = ""
    action_desc = None
    action2_desc = None

    def init(self):
        self.action_desc =  idaapi.action_desc_t(
            ACTION_NAME,
            ACTION_LABEL,
            InterfaceSpecializer(),
            None,
            self.comment,
            -1
        )
        ida_kernwin.register_action(self.action_desc)
        self.hook = Hooks()
        self.hook.hook()
        print("[GO Interface Specializer] Plugin loaded!")

        return idaapi.PLUGIN_KEEP
    
    def term(self):
        ida_kernwin.unregister_action(self.action_desc.name)
        self.hook.unhook()
    
    def run(self, arg):
        pass

def PLUGIN_ENTRY():
    return InterfaceSpecializerPlugin()