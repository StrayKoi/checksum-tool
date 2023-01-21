import hashlib
import dearpygui.dearpygui as dpg


def location(user_data, sender):
    UserInputs.file_location = sender


def src_checksum(user_data, sender):
    UserInputs.check_hash = sender


def apply(sender, value, user_data):
    try:
        md5 = hashlib.md5(open(UserInputs.file_location,'rb').read())
        sha1 = hashlib.sha1(open(UserInputs.file_location,'rb').read())
        sha256 = hashlib.sha256(open(UserInputs.file_location, 'rb').read())
        sha512 = hashlib.sha512(open(UserInputs.file_location, 'rb').read())

        # Calculate hash contents 
        with open(UserInputs.file_location, 'rb') as f:
            # read contents of file
            data = f.read()
            # pipe contents of file through
            UserInputs.md5 = hashlib.md5(data).hexdigest().upper()
            UserInputs.sha1 = hashlib.sha1(data).hexdigest().upper()
            UserInputs.sha256 = hashlib.sha256(data).hexdigest().upper()
            UserInputs.sha512 = hashlib.sha512(data).hexdigest().upper()
        
        if UserInputs.check_hash == UserInputs.md5:
            UserInputs.matched_hash = 'MD5'
        elif UserInputs.check_hash == UserInputs.sha1:
            UserInputs.matched_hash = 'SHA1'
        elif UserInputs.check_hash == UserInputs.sha256:
            UserInputs.matched_hash = 'SHA256'
        elif UserInputs.check_hash == UserInputs.sha512:
            UserInputs.matched_hash = 'SHA512'
        else:
            UserInputs.matched_hash = 'None'      
        
        show_hashes()
    
    except:
        return("Something went wrong.")


def show_hashes():
    dpg.delete_item('generate_hashes')
    
    # Delete Default Checksums Table & Rebuild
    with dpg.table(header_row=False, tag='generate_hashes', before='matched_hash'):
        dpg.add_table_column(width_fixed=True)
        dpg.add_table_column()

        # MD5
        with dpg.table_row():
            dpg.add_text('MD5:')
            dpg.add_input_text(default_value=UserInputs.md5, readonly=True, width=500)

        # SHA1
        with dpg.table_row():
            dpg.add_text('SHA1:')
            dpg.add_input_text(default_value=UserInputs.sha1, readonly=True, width=500)
        
        # SHA256
        with dpg.table_row():
            dpg.add_text('SHA256:')
            dpg.add_input_text(default_value=UserInputs.sha256, readonly=True, width=500)

        # SHA512
        with dpg.table_row():
            dpg.add_text('SHA512:')
            dpg.add_input_text(default_value=UserInputs.sha256, readonly=True, width=500)

        with dpg.table_row():
            # skip first column
            dpg.add_text('')
            # add message to second column
            if UserInputs.matched_hash == 'None':
                dpg.add_text(f' Hash matches {UserInputs.matched_hash}', color=(238, 75, 43))
            else:
                dpg.add_text(f' Hash matches {UserInputs.matched_hash}', color=(150, 255, 0))


class UserInputs():
    # User Info
    file_location = ''
    check_hash = ''
    # Generated Info
    md5 = ''
    sha1 = ''
    sha256 = ''
    sha512 = ''
    matched_hash = ''

dpg.create_context()

# Main Window
with dpg.window(tag="Primary Window"):
    dpg.add_spacer(height=3)

    with dpg.table(header_row=False):
        dpg.add_table_column(width_fixed=True)
        dpg.add_table_column()

        # Get File Location
        with dpg.table_row():
            dpg.add_text('File:')
            with dpg.group(horizontal=True):
                dpg.add_input_text(
                    width=510, 
                    callback=location, 
                    hint='Drive:\\\Location\Filename.ext',
                    )
                
        # Get Hash
        with dpg.table_row():
            dpg.add_text('Hash:')
            dpg.add_input_text(
                width=510, 
                callback=src_checksum, 
                hint='Paste hash here.', 
                no_spaces=True, 
                uppercase=True, 
                )

    dpg.add_spacer(height=3)
    dpg.add_separator()
    dpg.add_spacer(height=3)

    # Default Checksums Table
    with dpg.table(header_row=False, tag='generate_hashes', before='matched_hash'):
        dpg.add_table_column(width_fixed=True)
        dpg.add_table_column()

        # MD5
        with dpg.table_row():
            dpg.add_text('MD5:')
            dpg.add_input_text(hint='MD5 output.', readonly=True, width=500)

        # SHA1
        with dpg.table_row():
            dpg.add_text('SHA1:')
            dpg.add_input_text(hint='SHA1 output.', readonly=True, width=500)
        
        # SHA256
        with dpg.table_row():
            dpg.add_text('SHA256:')
            dpg.add_input_text(hint='SHA256 output.', readonly=True, width=500)

        # SHA512
        with dpg.table_row():
            dpg.add_text('SHA512:')
            dpg.add_input_text(hint='SHA512 output.', readonly=True, width=500)

        # Message Placeholder
        with dpg.table_row():
            dpg.add_text('')
        
    dpg.add_spacer(height=2, tag='matched_hash')
    dpg.add_separator()
    dpg.add_spacer(height=3)

    dpg.add_button(label='VERIFY', callback=apply)


dpg.create_viewport(title='Checksum Tool', width=600, height=365)
dpg.setup_dearpygui()
dpg.show_viewport()
dpg.set_primary_window("Primary Window", True)
dpg.start_dearpygui()
dpg.destroy_context()