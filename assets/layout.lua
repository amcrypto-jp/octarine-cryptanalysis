-- Keep the abstract with the title and place the contents on separate pages.
-- The Markdown document remains independent of this PDF-only formatting.
function Pandoc(doc)
  if not FORMAT:match("latex") then
    return doc
  end
  local blocks = pandoc.List()
  local inserted = false
  for _, block in ipairs(doc.blocks) do
    if not inserted and block.t == "Header" and block.level == 1
        and block.identifier ~= "abstract" then
      blocks:insert(pandoc.RawBlock("latex", [[
\clearpage
\begingroup
\small
\setlength{\parskip}{0pt}
\setcounter{tocdepth}{2}
\tableofcontents
\endgroup
\clearpage
]]))
      inserted = true
    end
    blocks:insert(block)
  end
  doc.blocks = blocks
  return doc
end
