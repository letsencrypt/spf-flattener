package spf

import (
	"fmt"
	"strings"
)

type Tree struct {
	root Node
}

func (t *Tree) Root() Node {
	return t.root
}

// Return list of names of nodes in subtree of input node
func (t *Tree) GetSubtree(node Node, listNodes []string) []string {
	listNodes = append(listNodes, node.GetName())
	for _, child := range node.GetChildren() {
		listNodes = append(listNodes, t.GetSubtree(child, []string{})...)
	}
	return listNodes
}

// Return list of names of nodes of ancestors of input node
func (t *Tree) GetAncestors(n Node) []string {
	listAncestors := []string{}
	node := n
	for node.GetParent() != nil {
		listAncestors = append([]string{node.GetParent().GetName()}, listAncestors...)
		node = node.GetParent()
	}
	return listAncestors
}

// Return node in tree with matching input name
func (t *Tree) FindNode(name string) Node {
	return t.FindSubtreeNode(t.Root(), name)
}

// Within subtree of input node, return node with matching input name
func (t *Tree) FindSubtreeNode(node Node, name string) Node {
	if node.GetName() == name {
		return node
	}
	for _, child := range node.GetChildren() {
		temp := t.FindSubtreeNode(child, name)
		if temp != nil {
			return temp
		}
	}
	return nil
}

func (t *Tree) PrintTree() {
	t.PrintSubtree(t.Root(), 0)
}

func (t *Tree) PrintSubtree(node Node, tabs int) {
	node.PrintNode(tabs)
	for _, child := range node.GetChildren() {
		t.PrintSubtree(child, tabs+1)
	}
}

type Node interface {
	GetName() string
	GetParent() Node
	GetChildren() []Node
	AddChild(Node)
	PrintNode(tabs int)
}

type node struct {
	name     string
	parent   Node
	children []Node
}

func (n *node) GetName() string {
	return n.name
}

func (n *node) GetParent() Node {
	return n.parent
}

func (n *node) GetChildren() []Node {
	return n.children
}

// Add input node to n's list of children
func (n *node) AddChild(child Node) {
	if n.children == nil {
		n.children = []Node{}
	}
	n.children = append(n.children, child)
}

func (n *node) PrintNode(tabs int) {
	listChildren := []string{}
	for _, child := range n.children {
		listChildren = append(listChildren, child.GetName())
	}
	fmt.Println(strings.Repeat("\t", tabs), n.GetName(), strings.Join(listChildren, ","))
}
