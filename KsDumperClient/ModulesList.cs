using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace KsDumperClient
{
    public partial class ModulesList : Form
    {
        public ModulesList(string processName, ModuleSummary[] modules)
        {
            InitializeComponent();

            this.Text = "Modules for [" + processName + "]";

            modules_view.Clear();
            modules_view.Items.Clear();

            modules_view.Columns.Add("DllBase", 120);
            modules_view.Columns.Add("SizeOfImage", 80);
            modules_view.Columns.Add("BaseDllName", 120);
            modules_view.Columns.Add("FullDllName", 400);

            foreach (ModuleSummary module in modules)
            {
                ListViewItem Item = new ListViewItem();

                Item.SubItems[0].Text = String.Format("{0:X16}", module.DllBase);
                Item.SubItems.Add(module.SizeOfImage.ToString());
                Item.SubItems.Add(module.BaseDllName);
                Item.SubItems.Add(module.FullDllName);

                modules_view.Items.Add(Item);
            }
        }
    }
}
